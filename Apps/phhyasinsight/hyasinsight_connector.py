#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom Hyas Insight App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals
import sys
import json
import requests
from bs4 import BeautifulSoup

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from hyasinsight_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class HyasInsightConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(HyasInsightConnector, self).__init__()
        # Variable to hold a _state in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        self._state = None
        self._apikey = None
        self._headers = None
        self._csrf_token= None
        self._login_url = self._get_phantom_base_url() + "/login"
    def get_csrf_token(self,verify):
        login_url = self._get_phantom_base_url() + "/login"

        print("Accessing the Login page")
        r = requests.get(login_url, verify=verify)
        self._csrftoken = r.cookies["csrftoken"]

    def get_session_id(self,username,password,verify):
        data = {}

        data["username"] = username
        data["password"] = password
        data["csrfmiddlewaretoken"] = self._csrf_token

        headers = {}
        headers["Cookie"] = "csrftoken=" + self._csrf_token
        headers["Referer"] = self._login_url
        self._headers=headers

        print("Logging into Platform to get the session id")
        r2 = requests.post(self.login_url, verify=verify, data=data, headers=headers)
        self.session_id = r2.cookies["sessionid"]


    def _get_error_message_from_exception(self, error):
        """This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        try:
            if error.args:
                if len(error.args) > 1:
                    error_code = error.args[0]
                    error_msg = error.args[1]
                elif len(error.args) == 1:
                    error_code = HYAS_ERR_CODE_MSG
                    error_msg = error.args[0]
            else:
                error_code = HYAS_ERR_CODE_MSG
                error_msg = HYAS_ERR_MSG_UNAVAILABLE
        except:
            error_code = HYAS_ERR_CODE_MSG
            error_msg = HYAS_ERR_MSG_UNAVAILABLE

        try:
            if error_code in HYAS_ERR_CODE_MSG:
                error_text = f"Error Message: {error_msg}"
            else:
                error_text = f"Error Code: {error_code}. Error Message: {error_msg}"

        except:
            error_text = HYAS_PARSE_ERR_MSG

        return error_text

    def _process_empty_response(self, response, action_result):
        """This function is used to check the empty response."""

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"
        if 200 <= response.status_code < 205:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    HYAS_HTML_ERR_MSG,
                ),
                None,
            )

        message = f"Status Code: {response.status_code}. Data from server:{error_text}"
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            self.save_progress("Cannot parse JSON")
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Unable to parse JSON response. Error: {str(e)}",
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 205:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        if resp_json.get("status") and resp_json.get("detail"):
            error_details = {
                "message": resp_json.get("status"),
                "detail": resp_json.get("detail"),
            }
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error from server, Status Code: {r.status_code} data returned: {error_details['detail']}",
                ),
                None,
            )
        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR,
                f"Error from server, Status Code: {r.status_code} data returned: {r.text}",
            ),
            None,
        )

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = (
            f"Can't process response from server."
            f" Status Code: {r.status_code} Data from server: {r.text}"
        )
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def flatten_json(self, response):

        json_flatten = {}

        def flatten(json_data, name=""):

            # If the Nested key-value
            # pair is of dict type
            if isinstance(json_data, dict):
                for json_data_in in json_data:
                    flatten(json_data[json_data_in], name + json_data_in + "_")

            # If the Nested key-value
            # pair is of list type
            elif isinstance(json_data, list):
                if len(json_data) > 0:
                    for json_data_in in json_data:
                        if isinstance(json_data_in, dict):
                            flatten(json_data_in, name)
                        else:
                            json_flatten[name[:-1]] = json_data
                else:
                    flatten("", name)
            else:
                json_flatten[name[:-1]] = json_data

        flatten(response)
        return json_flatten

    def get_flatten_json_response(self, raw_api_response):
        """

        :param raw_api_response: raw_api response from the API
        :return: Flatten Json response

        """
        flatten_json_response = []
        if raw_api_response:
            for obj in raw_api_response:
                flatten_json_response.append(self.flatten_json(obj))

        return flatten_json_response

    def _make_rest_call(
        self, endpoint, action_result, data=None, headers=None, method="post"
    ):
        # **kwargs can be any additional parameters that requests.request accepts
        try:
            request_func = getattr(requests, method)

        except AttributeError:
            # Set the action_result status to error,
            # the handler function will most probably return as is
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Unsupported method: {method}"
                ),
                None,
            )

        except Exception as e:
            # Set the action_result status to error,
            # the handler function will most probably return as is
            error_message = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Handled exception: {error_message}"
                ),
                None,
            )

        # Create a URL to connect to
        if endpoint == CURRENT_WHOIS:
            url = f"{CURRENT_WHOIS_BASE_URL}{endpoint}"
        else:
            url = f"{HYAS_BASE_URL}{endpoint}"

        try:
            response = request_func(url, data=data, headers=headers)

        except Exception as e:
            # Set the action_result status to error,
            # the handler function will most probably return as is
            error_message = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Error connecting: {error_message}"
                ),
                None,
            )

        return self._process_response(response, action_result)

    def validating_ioc(self, action_result, ioc, val):
        """
        Function that checks given ioc and return True if ioc is valid IP/Domain/Email/Phone/SHA256.
        :param ioc: IP address/Email/Phone/SHA256/Domain
        :return: status (success/failure)
        """
        try:
            if ioc in IOC_NAME:
                return bool(re.fullmatch(IOC_NAME[ioc], val))
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to locate ioc type."
                ),
                None,
            )
        except:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error while Validating the ioc"
                ),
                None,
            )

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.
        payload = json.dumps(
            {"applied_filters": {HYAS_TEST_PAYLOAD_KEY: HYAS_TEST_PAYLOAD_VALUE}}
        )

        self.save_progress("Connecting to endpoint")

        # make rest call
        ret_val, response = self._make_rest_call(
            HYAS_TEST_PASSIVEHASH_ENDPOINT,
            action_result,
            data=payload,
            headers=self._headers,
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            self.save_progress(HYAS_TEST_CONN_FAILED)
            return action_result.get_status()

        # Return success

        self.save_progress(HYAS_TEST_CONN_PASSED)
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary

    def _handle_all_actions(self, param):
        all_response = {}
        action_id = self.get_action_identifier()
        self.save_progress(f"In action handler for: {action_id}")
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            input_param = action_id
            if input_param in IOC_DETAILS:
                endpoint = IOC_DETAILS[input_param]["endpoint"]
                validating_ioc = self.validating_ioc(
                    action_result,
                    IOC_DETAILS[input_param]["indicator_type"],
                    param[ACTION_ID_PARAM[input_param]],
                )

                if validating_ioc:
                    if endpoint == CURRENT_WHOIS:
                        payload = json.dumps(
                            {
                                "applied_filters": {
                                    IOC_DETAILS[input_param]["indicator_type"]: param[ACTION_ID_PARAM[input_param]],
                                    "current": True,
                                }
                            }
                        )
                    else:
                        payload = json.dumps(
                            {
                                "applied_filters": {
                                    IOC_DETAILS[input_param]["indicator_type"]: param[ACTION_ID_PARAM[input_param]]
                                }
                            }
                        )

                    ret_val, response = self._make_rest_call(
                        endpoint,
                        action_result,
                        data=payload,
                        headers=self._headers,
                    )

                    if phantom.is_fail(ret_val):
                        return ret_val
                    
                    try:
                        if endpoint == SSL:
                            
                            response = response.get(SSL_CERTS)
                            
                        if endpoint == CURRENT_WHOIS:
                            response = response.get(ITEMS)
                            endpoint = CURRENT_WHOIS_NAME
                        
                        all_response[endpoint] = self.get_flatten_json_response(
                            response
                        )
                        
                        
                        action_result.add_data(all_response)
                        return action_result.set_status(phantom.APP_SUCCESS)
                    except:
                        return action_result.set_status(
                            phantom.APP_ERROR,
                            "unable to flatten json response.",
                            None,
                        )

            else:
                return action_result.set_status(
                    phantom.APP_ERROR, HYAS_ASSET_ERR_MSG, None
                )

        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Unable to retrieve actions results. Error: {str(e)}",
                None,
            )
        return action_result.set_status(
            phantom.APP_ERROR, HYAS_ERR_MSG_INVALID_INDICATOR_VALUE
        )

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id in ACTION_ID:
            ret_val = self._handle_all_actions(param)
        elif action_id in "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def _initialize_error(self, msg, exception=None):
        if self.get_action_identifier() == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            self.save_progress(msg)
            self.save_progress(self._get_error_message_from_exception(exception))
            self.set_status(phantom.APP_ERROR, "Test Connectivity Failed")
        else:
            self.set_status(phantom.APP_ERROR, msg, exception)
        return phantom.APP_ERROR

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        try:
            config = self.get_config()
        except Exception:
            return phantom.APP_ERROR
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """
        try:
            self._apikey = config[HYAS_JSON_APIKEY]
        except KeyError as ke:
            return self._initialize_error(
                HYAS_ERR_ASSET_API_KEY_,
                Exception(f"KeyError: {ke}"),
            )

        self._headers = {
            HYAS_JSON_APIKEY_HEADER: self._apikey,
            "Content-Type": "application/json",
        }

        # self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="verify",
        required=False,
        default=False,
    )

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        connector = HyasInsightConnector()
        connector.print_progress_message = True
        try:
            connector.get_csrf_token(verify)
            connector.get_session_id(username,password,verify)
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        #connector = HyasInsightConnector()


        if connector.session_id is not None:
            in_json["user_session_token"] = connector.session_id
            connector._set_csrf_info(connector._csrf_token, connector._header["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    sys.exit(0)


if __name__ == "__main__":
    main()
