#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

from GoogleFindMyTools.Auth.token_retrieval import request_token
from GoogleFindMyTools.Auth.username_provider import get_username

def get_adm_token(username):
    return request_token(username, "android_device_manager")


if __name__ == '__main__':
    print(get_adm_token(get_username()))