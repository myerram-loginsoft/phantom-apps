# File: virustotalv3_view.py
#
# Copyright (c) 2021-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
def _get_ctx_result(result, provides):
    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["check_param"] = False

    if len(param.keys()):
        ctx_result["check_param"] = True

    ctx_result['param'] = param
    ctx_result["action_name"] = provides
    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def display_view(provides, all_app_runs, context):
    context['results'] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    actions = {'lookup c2 domain': 'hyasinsight_display_view.html',
               'lookup c2 email': 'hyasinsight_display_view.html',
               'lookup c2 ip': 'hyasinsight_display_view.html',
               'lookup c2 sha256': 'hyasinsight_display_view.html',
               'lookup whois domain': 'hyasinsight_display_view.html',
               'lookup device geo ipv4': 'hyasinsight_display_view.html',
               'lookup device geo ipv6': 'hyasinsight_display_view.html',
               'lookup whois email': 'hyasinsight_display_view.html',
               'lookup whois phone': 'hyasinsight_display_view.html',
               'lookup dynamicdns ip': 'hyasinsight_display_view.html',
               'lookup dynamicdns email': 'hyasinsight_display_view.html',
               'lookup sinkhole ip': 'hyasinsight_display_view.html',
               'lookup passivehash ip': 'hyasinsight_display_view.html',
               'lookup passivehash domain': 'hyasinsight_display_view.html',
               'lookup passivedns ip': 'hyasinsight_display_view.html',
               'lookup passivedns domain': 'hyasinsight_display_view.html',
               'lookup ssl certificate ip': 'hyasinsight_display_view.html',
               'lookup current whois domain': 'hyasinsight_display_view.html'
               }
    return actions[provides]
    # if provides == 'lookup c2 domain':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup c2 email':a
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup c2 ip':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup c2 sha256':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup whois domain':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup device geo ipv4':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup device geo ipv6':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup whois email':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup whois phone':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup dynamicdns ip':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup dynamicdns email':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup sinkhole ip':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup passivehash ip':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup passivehash domain':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup passivedns ip':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup passivedns domain':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup ssl certificate ip':
    #     return 'hyasinsight_display_view.html'
    # elif provides == 'lookup current whois domain':
    #     return 'hyasinsight_display_view.html'
