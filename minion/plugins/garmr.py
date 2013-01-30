# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import json
import os
from minion.plugin_api import ExternalProcessPlugin

def _get_test_name(s):
    return s.split('.')[-1]

def parse_garmr_output(output):
    report = json.loads(output)
    urls = report.keys()
    if len(urls) == 1:
        url = urls[0]
        for category in report[url].keys():
            for check,results in report[url][category]['passive'].items():            
                if results['state'] == 'Fail':
                    yield {'Summary': "%s/%s Failed" % (_get_test_name(category), _get_test_name(check)),
                           'Severity': 'High',
                           'Description': results['message'],
                           'URLs': [url]}
    

class GarmrPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "Garmr"
    PLUGIN_VERSION = "0.1"

    GARMR_NAME = "garmr"
    GARMR_ARGS = ['-r', 'json', '-o', '/dev/stdout', '-e', 'StrictTransportSecurityPresent', '-u']

    def do_start(self):
        garmr_path = self.locate_program(self.GARMR_NAME)
        if garmr_path is None:
            raise Exception("Cannot find garm in path")
        self.output = ""
        self.spawn(garmr_path, self.GARMR_ARGS + [self.configuration['target']])

    def do_process_stdout(self, data):
        self.output += data

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            self.callbacks.report_issues(list(parse_garmr_output(self.output)))
            self.callbacks.report_finish()
        else:
            self.report_finish("FAILED")
