from dotenv import load_dotenv
import requests
import logging
import json
import logging.handlers as handlers
import os
import sys
from dataclasses import dataclass
from http import HTTPStatus
import time
from os import environ
import argparse

DEFAULT_360_SCIM_API_URL = "https://{domain_id}.scim-api.passport.yandex.net/"
DEFAULT_360_API_URL = "https://api360.yandex.net"
ITEMS_PER_PAGE = 100
MAX_RETRIES = 3
LOG_FILE = "change_scim_user_name.log"
RETRIES_DELAY_SEC = 2
SLEEP_TIME_BETWEEN_API_CALLS = 0.5

EXIT_CODE = 1

logger = logging.getLogger("change_scim_user_name")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
#file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30, encoding='utf-8')
file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=10* 1024 * 1024,  backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)
logger.addHandler(file_handler)

@dataclass
class SettingParams:
    scim_token: str
    oauth_token: str
    domain_id: int  
    org_id: int
    users_file : str
    new_login_default_format : str

def get_settings():
    exit_flag = False
    settings = SettingParams (
        scim_token = os.environ.get("SCIM_TOKEN_ARG"),
        domain_id = os.environ.get("SCIM_DOMAIN_ID_ARG"),
        users_file = os.environ.get("USERS_FILE_ARG"),
        new_login_default_format = os.environ.get("NEW_LOGIN_DEFAULT_FORMAT_ARG"),
        oauth_token = os.environ.get("OAUTH_TOKEN_ARG"),
        org_id = os.environ.get("ORG_ID_ARG"),

    )

    if not settings.scim_token:
        logger.error("SCIM_TOKEN_ARG is not set")
        exit_flag = True

    if settings.domain_id.strip() == "":
        logger.error("SCIM_DOMAIN_ID_ARG is not set")
        exit_flag = True

    if not settings.users_file:
        logger.error("USERS_FILE_ARG is not set")
        exit_flag = True

    if not settings.new_login_default_format:
        settings.new_login_default_format = "alias@domain.tld"
    
    if not settings.oauth_token:
        logger.error("OAUTH_TOKEN_ARG is not set")
        exit_flag = True

    if not settings.org_id:
        logger.error("ORG_ID_ARG is not set")
        exit_flag = True

    if not check_scim_token(settings.scim_token, settings.domain_id):
        logger.error("SCIM_TOKEN_ARG is not valid")
        exit_flag = True

    if not check_oauth_token(settings.oauth_token, settings.org_id):
        logger.error("OAUTH_TOKEN_ARG is not valid")
        exit_flag = True
    
    if exit_flag:
        return None
    
    return settings

def check_scim_token(scim_token, domain_id):
    """Проверяет, что токен SCIM действителен."""
    url = DEFAULT_360_SCIM_API_URL.format(domain_id=domain_id) 
    headers = {
        "Authorization": f"Bearer {scim_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(f"{url}/v2/Users?startIndex=1&count=100", headers=headers)
    if response.status_code == HTTPStatus.OK:
        return True
    return False

def check_oauth_token(oauth_token, org_id):
    """Проверяет, что токен OAuth действителен."""
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{org_id}/users?perPage=100"
    headers = {
        "Authorization": f"OAuth {oauth_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == HTTPStatus.OK:
        return True
    return False

def parse_arguments():
    """Парсит позиционные аргументы командной строки."""
    parser = argparse.ArgumentParser(
        description="Script for changing userName attribute in Yandex 360 API SCIM or nickname attribute in Yandex 360 API.\n"
                    "Command line arguments: old new attribute [confirm]",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "old",
        help="Old userName",
        type=str,
        nargs="?",
        default=None
    )
    parser.add_argument(
        "new",
        help="New userName",
        type=str,
        nargs="?",
        default=None
    )
    parser.add_argument(
        "attribute",
        help="userName or nickname",
        choices=["userName", "username", "nickname"],
        type=str.lower,
        nargs="?",
        default=None
    )
    parser.add_argument(
        "confirm",
        help="Confirm? (yes или no)",
        choices=["yes", "no"],
        type=str.lower,
        nargs="?",
        default=None
    )
    return parser.parse_args()

def interactive_mode(settings: "SettingParams"):
    """Интерактивный режим для ввода параметров."""

    value = input("Enter old and new value of userName, separated by space: ").strip()
    if not value:
        logger.error("String can not be empty.")
        return
    
    if len(value.split()) != 2:
        logger.error("There must be exactly two arguments.")
        return
    
    old_value, new_value = value.split()
    single_mode(settings, old_value, new_value)

def single_mode(settings: "SettingParams", old_value, new_value):
    users = users = get_all_scim_users(settings)
    if users:
        old_user = next((item for item in users if item["userName"] == old_value.lower()), None)
        if not old_user:
            logger.error(f"User {old_value} not found.")
            return
        new_user= next((item for item in users if item["userName"] == new_value.lower()), None)
        if new_user:
            logger.error(f"User {old_value} already exist in system. Select another new value for userName.")
            return
        logger.info(f"User {old_value} found. UID: {old_user['id']}. Start changing userName to {new_value}...")
        uid = old_user["id"]
        headers = {
                "Authorization": f"Bearer {settings.scim_token}"
                    }
        url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id)
        try:
            retries = 1
            while True:
                data = json.loads("""   { "Operations":    
                                            [
                                                {
                                                "value": "alias@domain.tld",
                                                "op": "replace",
                                                "path": "userName"
                                                }
                                            ],
                                            "schemas": [
                                                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                                            ]
                                        }""".replace("alias@domain.tld", new_value))
                
                response = requests.patch(f"{url}/v2/Users/{uid}", headers=headers, json=data)
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        logger.error(f"Error. Patching user {old_value} to {new_value} failed.")
                        break
                else:
                    logger.info(f"Success - User {old_value} changed to {new_value}.")
                    break

        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
    else:
        logger.debug(f"List of users is empty.")

def main(settings: "SettingParams"):
    """Основная функция скрипта."""
    try:
        args = parse_arguments()
        old_value = args.old
        new_value = args.new
        attribute = args.attribute
        confirm = args.confirm

        # Подсчёт переданных параметров
        provided_params = sum(1 for arg in [old_value, new_value, confirm] if arg is not None)
        interactive_mode = False
        # Проверка количества параметров
        if provided_params < 3:
            logger.info("There is only one command line argument, start interactive mode.")
            interactive_mode = True
        elif provided_params == 3 and old_value is not None and new_value is not None and attribute is not None:
            confirm = confirm if confirm else "no"
        elif provided_params == 4:
            pass
        else:
            logger.error("Wrong agruments count, start interactive mode.")
            interactive_mode = True

        logger.debug(f"Command line arguments: old={old_value}, new={new_value}, attribute={attribute}, confirm={confirm}")

        if interactive_mode:
            main_menu(settings)
        else:
            # Проверка подтверждения
            if confirm == "yes":
                logger.info("Confirmation received (confirm=yes), start renaming.")
                if attribute.lower() == "username":
                    single_mode(settings, old_value, new_value)
                elif attribute.lower() == "nickname":
                    change_nickname(settings, old_value, new_value)
            else:
                logger.info("Need confirmation.")
                answer = input("Need confirmation (yes/no): ").strip().lower()
                while answer not in ["yes", "no"]:
                    logger.warning("Enter 'yes' или 'no'")
                    answer = input("Need confirmation (yes/no): ").strip().lower()
                if answer == "yes":
                    if attribute.lower() == "username":
                        single_mode(settings, old_value, new_value)
                    elif attribute.lower() == "nickname":
                        change_nickname(settings, old_value, new_value)
                else:
                    logger.info("Execution canceled.")
                    sys.exit(0)

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        sys.exit(1)

def main_menu(settings: "SettingParams"):

    while True:
        print("\n")
        print("-------------------------- Config params ---------------------------")
        print(f'New loginName format: {settings.new_login_default_format}')
        print("--------------------------------------------------------------------")
        print("\n")

        print("Select option:")
        print("1. Set new loginName format (default: alias@domail.tld).")
        print("2. Check alias for users.")
        print("3. Save user info to file.")
        print("4. Download current SCIM users into file.")
        print("5. Use users file to change SCIM loginName of users.")
        print("6. Enter old and new value of userName manually and confirm renaming.")
        print("7. Change nickname of single user.")
        
        print("0. Exit")

        choice = input("Enter your choice (0-7): ")

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            print('\n')
            set_new_loginName_format(settings)
        elif choice == "2":
            print('\n')
            check_alias_prompt(settings)
        elif choice == "3":
            print('\n')
            save_user_data_prompt(settings)    
        elif choice == "4":
            print('\n')
            download_users_to_file(settings)
        elif choice == "5":
            print('\n')
            update_users_from_file(settings)
        elif choice == "7":
            print('\n')
            change_nickname_prompt(settings)
        elif choice == "6":
            interactive_mode(settings)
        else:
            print("Invalid choice. Please try again.")

def set_new_loginName_format(settings: "SettingParams"):
    answer = input("Enter format of new userLogin name (space to use default format alias@domain.tld):\n")
    if answer:
        if answer.strip() == "":
            settings.new_login_default_format = "alias@domain.tld"
        else:
            settings.new_login_default_format = answer.strip()

    return settings

def get_all_api360_users(settings: "SettingParams"):
    logger.info("Getting all users of the organisation...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users?perPage=100"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    try:
        response = requests.get(url, headers=headers)
        if response.ok:
                users = response.json()['users']
                for i in range(2, response.json()["pages"] + 1):
                    response = requests.get(f"{url}&page={i}", headers=headers)
                    if response.ok:
                        users.extend(response.json()['users'])

    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    return users

def get_all_scim_users(settings: "SettingParams"):
    logger.info("Getting all users of the organisation from SCIM...")
    users = []
    headers = {
        "Authorization": f"Bearer {settings.scim_token}"
    }
    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id)
    startIndex = 1
    items = ITEMS_PER_PAGE
    try:
        retries = 1
        while True:           
            response = requests.get(f"{url}/v2/Users?startIndex={startIndex}&count={items}", headers=headers)
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Forcing exit without getting data.")
                    return
            else:
                retries = 1
                temp_list = response.json()["Resources"]
                logger.debug(f'Received {len(temp_list)} records.')
                users.extend(temp_list)

                if int(response.json()["startIndex"]) + int(response.json()["itemsPerPage"]) > int(response.json()["totalResults"]) + 1:
                    break
                else:
                    startIndex = int(response.json()["startIndex"]) + int(response.json()["itemsPerPage"])

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    
    return users

def change_nickname_prompt(settings: "SettingParams"):
    data = input("Enter old value and new value of nickname separated by space (empty sting to exit): ")
    if len(data.strip()) == 0:
        return
    elif len(data.split()) != 2:
        logger.error("Invalid input. Please enter old value and new value separated by space.")
        return
    else:
        old_value, new_value = data.split()
        change_nickname(settings, old_value, new_value)

def check_alias_prompt(settings: "SettingParams"):
    data = input("Enter alias (without domain) to check (empty sting to exit): ")
    if len(data.strip()) == 0:
        return
    elif len(data.split("@")) == 2:
        data=data.split("@")[0]

    check_alias(settings, data.lower())

def check_alias(settings: "SettingParams", alias: str):
    logger.info(f"Checking alias {alias}")
    users = get_all_api360_users(settings)
    if not users:
        logger.error("No users found.")
    logger.info(f"{len(users)} users found.")
    
    for user in users:
        if alias == user['nickname']:
            logger.info(f"Alias _ {alias} _ already exists as nickname in user with nickname {user['nickname']}. User ID - {user['id']}.  User displayName - {user.get('displayName','')}.")
        if alias in user['aliases']:
            logger.info(f"Alias _ {alias} _ already exists as alias in user with nickname {user['nickname']}. User ID - {user['id']}.  User displayName - {user.get('displayName','')}.")
        for contact in user['contacts']:
            if contact['type'] == 'email' and contact['value'].split('@')[0] == alias:
                logger.info(f"Alias _ {alias} _ already exists as email contact in user with nickname {user['nickname']}. User ID - {user['id']}. User displayName - {user.get('displayName','')}.")

    scim_users = get_all_scim_users(settings)
    if not scim_users:
        logger.error("No users found.")
    for user in scim_users:
        if alias == user['userName'] or alias == user['userName'].split('@')[0]:
            logger.info(f"Alias _ {alias} _ already exists as userName in _SCIM_ user with ID - {user['id']}.  User displayName - {user['displayName']}.")

def change_nickname(settings: "SettingParams", old_value: str, new_value: str):
    logger.info(f"Changing nickname of user {old_value} to {new_value}")
    users = get_all_api360_users(settings)
    
    if not users:
        logger.error("No users found.")
        return
    logger.info(f"{len(users)} users found.")

    target_user = [user for user in users if user['nickname'] == old_value]
    if not target_user:
        logger.error(f"User with nickname {old_value} not found.")
        return
    logger.info(f"User with nickname {old_value} found. User ID - {target_user[0]['id']}")

    existing_user = [user for user in users if user['nickname'] == new_value]
    if existing_user:
        logger.error(f"User with nickname {new_value} already exists. User ID - {existing_user[0]['id']}. Clear this nickname and try again.")
        return
    
    for user in users:
        if new_value in user['aliases'] and user['nickname'] != old_value:
            logger.error(f"Nickname {new_value} already exists as alias in user with nickname {user['nickname']}. User ID - {user['id']}. Clear this alias in this user and try again.")
            return
        if user['nickname'] != old_value:
            for contact in user['contacts']:
                if contact['type'] == 'email' and contact['value'].split('@')[0] == new_value:
                    logger.error(f"Nickname {new_value} already exists as email contact in user with nickname {user['nickname']}. User ID - {user['id']}. Clear this contact email in this user and try again.")
                    return
    
    if new_value in target_user[0]['aliases']:
        remove_alias_in_scim(target_user[0]["id"], new_value)

    for contact in target_user[0]['contacts']:
        if contact['type'] == 'email' and contact['value'].split('@')[0] == new_value:
            remove_email_in_scim(target_user[0]["id"], new_value)

    logger.info(f"Changing nickname of user {old_value} to {new_value}")
    raw_data = {'nickname': new_value}
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{target_user[0]['id']}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    try:
        response = requests.patch(url, headers=headers, data=json.dumps(raw_data))
        if response.ok:
            logger.info(f"Nickname of user {old_value} changed to {new_value}")
            time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
        else:
            logger.error(f"Error ({response.status_code}) changing nickname of user {old_value} to {new_value}: {response.text}")
            return

    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return 
    
    remove_alias_in_scim(target_user[0]["id"], old_value)
    remove_email_in_scim(target_user[0]["id"], old_value)

def remove_alias_in_scim(user_id: str, alias: str):
    logger.info(f"Check if exist and removing alias {alias} in _SCIM_ user {user_id}")

    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id)
    headers = {"Authorization": f"Bearer {settings.scim_token}"}
    try:
        response = requests.get(f"{url}/v2/Users/{user_id}", headers=headers)
        if response.ok:
            user = response.json()
            if user['urn:ietf:params:scim:schemas:extension:yandex360:2.0:User']['aliases']:
                compiled_alias = {}
                compiled_alias["login"] = alias
                if compiled_alias in user['urn:ietf:params:scim:schemas:extension:yandex360:2.0:User']['aliases']:
                    user['urn:ietf:params:scim:schemas:extension:yandex360:2.0:User']['aliases'].remove(compiled_alias)

                    data = json.loads("""   { "Operations":    
                                                [
                                                    {
                                                    "value": _data_,
                                                    "op": "replace",
                                                    "path": "urn:ietf:params:scim:schemas:extension:yandex360:2.0:User.aliases"
                                                    }
                                                ],
                                                "schemas": [
                                                    "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                                                ]
                                            }""".replace("_data_", json.dumps(user['urn:ietf:params:scim:schemas:extension:yandex360:2.0:User']['aliases'])))

                    response = requests.patch(f"{url}/v2/Users/{user_id}", headers=headers, data=json.dumps(data))
                    if response.ok:
                        logger.info(f"Alias {alias} removed in user {user_id}")
                        time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
                    else:
                        logger.error(f"Error ({response.status_code}) removing alias {alias} in user {user_id}: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

def remove_email_in_scim(user_id: str, alias: str):
    logger.info(f"Check if exist and removing email with alias {alias} in _SCIM_ user {user_id} email info.")
    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id) 
    headers = {"Authorization": f"Bearer {settings.scim_token}"}
    try:
        response = requests.get(f"{url}/v2/Users/{user_id}", headers=headers)
        if response.ok:
            user = response.json()
            new_emails= []
            found_alias = False
            for email in user['emails']:
                temp = {}
                if email["value"].split('@')[0] != alias:
                    temp["primary"] = email["primary"]
                    if len(email.get("type",'')) > 0:
                        temp["type"] = email["type"]
                    temp["value"] = email["value"]
                    new_emails.append(temp)
                else:
                    found_alias = True
            
            if found_alias:
                data = json.loads("""   { "Operations":    
                                            [
                                                {
                                                "value": _data_,
                                                "op": "replace",
                                                "path": "emails"
                                                }
                                            ],
                                            "schemas": [
                                                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                                            ]
                                        }""".replace("_data_", json.dumps(new_emails)))

                response = requests.patch(f"{url}/v2/Users/{user_id}", headers=headers, data=json.dumps(data))
                if response.ok:
                    logger.info(f"Alias {alias} removed from email contacts in _SCIM_ user {user_id}")
                    time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
                else:
                    logger.error(f"Error ({response.status_code}) removing alias {alias} from email contacts in _SCIM_ user {user_id}: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")


def download_users_to_file(settings: "SettingParams", onlyList = False):

    users = get_all_scim_users(settings)

    if users:
        if not onlyList:
            with open(settings.users_file, "w", encoding="utf-8") as f:
                f.write("uid;displayName;old_userName;new_userName\n")
                for user in users:
                    new_userName = user["userName"]
                    if "@" in user["userName"]:
                        login = user["userName"].split("@")[0]
                        domain = ".".join(user["userName"].split("@")[1].split(".")[:-1])
                        tld = user["userName"].split("@")[1].split(".")[-1]
                        new_userName = settings.new_login_default_format.replace("alias", login).replace("domain", domain).replace("tld", tld)
                    f.write(f"{user['id']};{user['displayName']};{user['userName']};{new_userName}\n")
            logger.info(f"{len(users)} users downloaded to file {settings.users_file}")
    else:
        logger.info(f"No users found. Check your settings.")
        return []
    return users

def update_users_from_file(settings: "SettingParams"):
    user_for_change = []
    all_users = []
    with open(settings.users_file, "r", encoding="utf-8") as f:
        all_users = f.readlines()

    line_number = 1
    for user in all_users[1:]:
        line_number += 1
        if user.replace("\n","").strip():
            temp = user.replace("\n","").strip()
            try:
                uid, displayName, old_userName, new_userName = temp.split(";")
                if not any(char.isdigit() for char in uid):
                    logger.info(f"Uid {uid} is not valid ({displayName}). Skipping.")   
                    continue
                if not new_userName:
                    logger.info(f"New userName for uid {uid} ({displayName}) is empty. Skipping.")   
                    continue
                if old_userName == new_userName:
                    logger.debug(f"User {old_userName} ({displayName}) has the same new name {new_userName}. Skipping.")
                    continue
                user_for_change.append(temp)
            except ValueError as e:
                logger.error(f"Line number {line_number} has wrong count of values (should be 4 values, separated by semicolon. Skipping")

            except Exception as e:
                logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    
    if not user_for_change:
        logger.error(f"File {settings.users_file} is empty.")
        return
    else:
        for user in user_for_change:
            logger.debug(f"Will modify - {temp}.")

        answer = input(f"Modify userName SCIM attribute for {len(user_for_change)} users? (Y/n): ")
        if answer.upper() not in ["Y", "YES"]:
            return
        
    headers = {
        "Authorization": f"Bearer {settings.scim_token}"
    }
    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id) 
    for user in user_for_change:
        uid, displayName, old_userName, new_userName = user.strip().split(";")
        try:
            retries = 1
            while True:
                logger.info(f"Changing user {old_userName} to {new_userName}...")
                data = json.loads("""   { "Operations":    
                                            [
                                                {
                                                "value": "alias@domain.tld",
                                                "op": "replace",
                                                "path": "userName"
                                                }
                                            ],
                                            "schemas": [
                                                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                                            ]
                                        }""".replace("alias@domain.tld", new_userName))
                
                response = requests.patch(f"{url}/v2/Users/{uid}", headers=headers, json=data)
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        logger.error(f"Error. Patching user {old_userName} to {new_userName} failed.")
                        break
                else:
                    logger.info(f"Success - User {old_userName} changed to {new_userName}.")
                    break
                

        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

def save_user_data_prompt(settings: "SettingParams"):
    answer = input(f"Enter target user key in format: id:<UID> or userName:<SCIM_USER_NAME> or <API_360_NICKNAME> or <API_360_ALIAS> (empty string to exit): ")
    if not answer.strip():
        return
    if ":" in answer:
        key, value = answer.split(":")
        key = key.strip()
        value = value.strip().lower()
        if key.lower() not in ["id", "username"]:
            logger.error(f"Invalid key {key}. Please enter id:<UID> or userName:<SCIM_USER_NAME>.")
            return
    else:
        key = "nickname"
        value = answer.lower()

    if key == "id":
        if not any(char.isdigit() for char in value):
            logger.error(f"Invalid UID {value} (Must be numeric value). Please enter valid UID.")
            return

    logger.info(f"Saving user data for key {key} and value {value}.")
    users = get_all_api360_users(settings)
    scim_users = get_all_scim_users(settings)  
    if not users:
        logger.error(f"No users found from API 360 calls. Check your settings.")
        return
    if not scim_users:
        logger.error(f"No users found from SCIM calls. Check your settings.")
        return
    target_user = None
    target_scim_user = None
    if key in ["id", "nickname"]:
        for user in users:
            if key == "id":
                if user["id"] == value:
                    target_user = user
                    break
            elif key == "nickname":
                if user["nickname"] == value or value in user["aliases"]:
                    target_user = user
                    break
    elif key.lower() == "username":
        for user in scim_users:
            if user["userName"] == value:
                target_scim_user = user
                break
    
    if target_user:
        target_scim_user = [user for user in scim_users if user["id"] == target_user["id"]][0]
    elif target_scim_user:
        target_user = [user for user in users if user["id"] == target_scim_user["id"]][0]
    else:
        logger.error(f"No user found for key {key} and value {value}.")
        return
    
    logger.info("\n")
    logger.info(f"--------------------------------------------------------")
    logger.info(f'API 360 attributes for user with id: {target_user["id"]}')
    logger.info(f"--------------------------------------------------------")
    for k, v in target_user.items():
        if k.lower() == "contacts":
            logger.info(f"Contacts")
            for l in v: 
                for k1, v1 in l.items():  
                    logger.info(f" - {k1}: {v1}")
                logger.info(f" -")
        elif k.lower() == "aliases":
            logger.info(f"Aliases")
            for l in v:
                logger.info(f" - {l}")
        elif k.lower() == "name":
            logger.info(f"Name")
            for k1, v1 in v.items():  
                logger.info(f" - {k1}: {v1}")
        else:
            logger.info(f"{k}: {v}")
    logger.info(f"--------------------------------------------------------")
    logger.info(f"--------------------------------------------------------")
    logger.info(f'SCIM attributes for user with id: {target_scim_user["id"]}')
    logger.info(f"--------------------------------------------------------")
    for k, v in target_scim_user.items():
        if k.lower() == "emails":
            logger.info(f"Emails")
            for l in v:
                for k1, v1 in l.items():   
                    logger.info(f" - {k1}: {v1}")
                logger.info(f" -")
        elif k.lower() == "metadata":
            logger.info(f"Metadata")
            for k1, v1 in v.items():  
                logger.info(f" - {k1}: {v1}")
        elif k.lower() == "name":
            logger.info(f"name")
            for k1, v1 in v.items():  
                logger.info(f" - {k1}: {v1}")
        elif k.lower() == "meta":
            logger.info(f"meta")
            for k1, v1 in v.items():  
                logger.info(f" - {k1}: {v1}")
        elif k.lower() == "phonenumbers":
            logger.info(f"phoneNumbers")
            for l in v:
                for k1, v1 in l.items():  
                    logger.info(f" - {k1}: {v1}")
                logger.info(f" -")
        elif k == "urn:ietf:params:scim:schemas:extension:yandex360:2.0:User":
            logger.info(f"aliases")
            for l in v["aliases"]:
                for k1, v1 in l.items():
                    logger.info(f" - {k1}: {v1}")
        else:
            logger.info(f"{k}: {v}")
    logger.info(f"--------------------------------------------------------")
    logger.info("\n")
    with open(f"{target_user['nickname']}.txt", "w", encoding="utf-8") as f:
        f.write(f'API 360 attributes for user with id: {target_user["id"]}\n')
        f.write(f"--------------------------------------------------------\n")
        for k, v in target_user.items():
            if k.lower() == "contacts":
                f.write(f"Contacts\n")
                for l in v: 
                    for k1, v1 in l.items():  
                        f.write(f" - {k1}: {v1}\n")
                    f.write(f" -\n")
            elif k.lower() == "aliases":
                f.write(f"Aliases\n")
                for l in v:
                    f.write(f" - {l}\n")
            elif k.lower() == "name":
                f.write(f"Name\n")
                for k1, v1 in v.items():  
                    f.write(f" - {k1}: {v1}\n")
            else:
                f.write(f"{k}: {v}\n")
        f.write(f"--------------------------------------------------------\n")
        f.write(f"--------------------------------------------------------\n")
        f.write(f'SCIM attributes for user with id: {target_scim_user["id"]}\n')
        f.write(f"--------------------------------------------------------\n")
        for k, v in target_scim_user.items():
            if k.lower() == "emails":
                f.write(f"Emails\n")
                for l in v:
                    for k1, v1 in l.items():   
                        f.write(f" - {k1}: {v1}\n")
                    f.write(f" -\n")
            elif k.lower() == "metadata":
                f.write(f"Metadata\n")
                for k1, v1 in v.items():  
                    f.write(f" - {k1}: {v1}\n")
            elif k.lower() == "name":
                f.write(f"name\n")
                for k1, v1 in v.items():  
                    f.write(f" - {k1}: {v1}\n")
            elif k.lower() == "meta":
                f.write(f"meta\n")
                for k1, v1 in v.items():  
                    f.write(f" - {k1}: {v1}\n")
            elif k.lower() == "phonenumbers":
                f.write(f"phoneNumbers\n")
                for l in v:
                    for k1, v1 in l.items():  
                        f.write(f" - {k1}: {v1}\n")
                    f.write(f" -\n")
            elif k == "urn:ietf:params:scim:schemas:extension:yandex360:2.0:User":
                f.write(f"aliases")
                for l in v["aliases"]:
                    for k1, v1 in l.items():
                        f.write(f" - {k1}: {v1}\n")
            else:
                f.write(f"{k}: {v}\n")
        f.write(f"--------------------------------------------------------\n")
    logger.info(f"User attributes saved to file: {target_user['nickname']}.txt")

if __name__ == "__main__":

    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)

    logger.debug(f"Запуск скрипта.")
    settings = get_settings()

    try:
        main(settings)
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        sys.exit(EXIT_CODE)