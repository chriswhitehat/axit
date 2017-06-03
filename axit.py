#!/usr/bin/env python2
'''
Copyright (c) 2016 Chris White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import argparse, os, simplejson, requests, re, logging, datetime, sys, hashlib
from urllib2 import quote
from time import sleep

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-8s %(levelname)-6s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class bcolors:
    HEADER = '\033[94m'
    HEADER2 = '\033[95m'
    TITLE = '\033[44m'
    TITLE2 = '\033[105m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLDON = '\033[1m'
    BOLDOFF = '\033[0m'
    GREY = '\033[2m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''
        self.BOLDON = ''
        self.BOLDOFF = ''

colors = bcolors()


def processArgs(args=None):

    parser = argparse.ArgumentParser(description='axit, Send Files and URLs to FireEye MAS (AX) for analysis', prog='axit')

    parser.add_argument('-a', '--alerts', nargs="+", metavar="<alert_id>", default=[], help="retrieve alert form MAS (AX)")
    parser.add_argument('-b', '--blocking', action='store_true', help="submit analysis samples, poll until completion and return results")
    parser.add_argument('-i', '--infolevel', metavar="<concise|normal|extended>", default='concise', help="verbosity of the result and alert. Default: consise")
    parser.add_argument('-f', '--files', nargs="+", metavar="<filename>", help='list of files to submit to MAS (AX)')
    parser.add_argument('-l', '--live', action='store_true', help='analyze in live mode, default: sandbox mode')
    parser.add_argument('-n', '--noprefetch', action="store_true", help="disable prefetch")
    parser.add_argument('-o', '--priority', nargs=1, metavar="<priority>", default=0, help="priority of submission")
    parser.add_argument('-p', '--profiles', nargs="+", metavar="<analysis_profile>", default=["win7x64-sp1"], help="the guest images and profiles to using for analysis")
    parser.add_argument('-t', '--timeout', nargs=1, metavar="<seconds>", default=120, help="analysis timeout in seconds")
    parser.add_argument('-r', '--results', nargs="+", metavar="<list_id>", default=[], help="retrieve result form completed sandbox analysis")
    parser.add_argument('-s', '--status', nargs="+", metavar="<list_id>", default=[], help="retrieve status of submitted sandbox anslysis")
    parser.add_argument('-u', '--urls', nargs="+", metavar="<url>", help='list of URLs to submit to MAS (AX)')

    parser.add_argument('--force', action="store_true")
    parser.add_argument('--hostname', metavar="<ax hostname>", default='scfeax00099p01.corp.costco.com', help='fqdn hostname of MAS (AX)')
    parser.add_argument('--username', metavar="<ax username>", help='username to log into MAS (AX)')
    parser.add_argument('--password', metavar="<ax password>", help='password to log into MAS (AX)')
    parser.add_argument('--credential', metavar="<netrc-file>", default='/nsm/scripts/python/cirta/resources/fireeye/.feaxcred', help="path to a netrc-file formatted credential (see curl netrc-file)")
    parser.add_argument('--token', metavar="<ax token>", help='valid session token to run actions on the MAS (AX)')
    parser.add_argument('--debug', action="store_true", help='turn debug logging on.')

    if args is not None:
        return parser.parse_args(args)
    else:
        return parser.parse_args()


class AXObject(object):
    def __init__(self, alertID=None, submission=None, submissionType=None):
        self.status = None
        self.error = None
        self.result = None
        self.subID = None
        self.malicious = None

        self.submission = submission
        self.submissionType = submissionType

        self.alertID = alertID

        self.setupSubmission()


    def setupSubmission(self):
        if self.submissionType == 'urls':
            logger.debug('Adding url %s' % self.submission)

            self.urls = []
            if isinstance(self.submission, str):
                self.urls.append(self.submission)
            elif isinstance(self.submission, list):
                self.urls.extend(self.submission)

        elif self.submissionType == 'files':
            self.files = []
            if os.path.exists(self.submission):
                logger.debug('Adding file %s' % self.submission)
                self.files.append(('filename', (os.path.basename(self.submission), open(self.submission, 'rb'), 'application/octet-stream')))
            else:
                logger.warn('Failed to add file, does not exist: %s' % self.submission)

            if not self.files:
                logger.warn('No files in this submission were successfully added.')
                self.status = 'Failed'
                self.error = 'File does not exist'

    def setAlertID(self, result):
        if 'id' in result:
            self.alertID = result['id']
        elif 'ID' in result:
            self.alertID = result['ID']

    def setSubmissionID(self, result):
        self.subID = result['entity']['response'][0]['id']

    def setResult(self, result):
        self.result = result

        if 'alertsCount' in self.result and self.result['alertsCount'] > 0:
            self.malicious = True
        else:
            self.malicious = False

        self.status = 'Completed'

    def setStatus(self, statusJSON):

        if self.alertID:
            if statusJSON['submissionStatus'] == 'Submission not found':
                self.status = 'Failed'
            else:
                self.status = statusJSON['submissionStatus']
        elif self.subID:
            if statusJSON['status'] == 'Submission not found':
                self.status = 'Failed'
            else:
                self.setAlertID(statusJSON['response'][0])

        logger.debug(self.status)

    def processCode(self, response):
        print("Error: %s" % (response.reason))
        self.error = response.reason
        self.status = 'Failed'



class FireEyeAX(object):
    def __init__(self, options):
        self.token = None
        self.options = options
        self.submissions = []
        self.completed = []
        self.sleepTime = 10
        self.progressPos = 0
        self.hashes = []
        self.urls = []

        if options.alerts:
            self.submissions.extend([AXObject(alertID=alert) for alert in options.alerts])
        if options.urls:
            self.submissions.extend([AXObject(submission=url, submissionType='urls') for url in self.checkURLs(options.urls)])
        if options.files:
            self.submissions.extend([AXObject(submission=subFile, submissionType='files') for subFile in self.checkHashes(options.files)])
        self.hostname = options.hostname
        self.username = options.username
        self.password = options.password
        self.credential = options.credential

        self.polls = 0

        self.login()


    def printStatus(self, sub, verdict, color):
        subStatus = "Submission %s" % sub
        print("%-70s [ %s%s%s ]" % (subStatus, color, verdict, colors.ENDC))


    def checkHashes(self, files):
        procFiles = []
        for f in files:
            with open(f, 'rb') as fBinary:
                md5 = hashlib.md5(fBinary.read()).hexdigest()
                if md5 not in self.hashes:
                    self.hashes.append(md5)
                    procFiles.append(f)
                    self.printStatus(f, 'Submitting', colors.OKBLUE)
                else:
                    self.printStatus(f, 'Duplicate', colors.WARNING)
        return procFiles
    

    def checkURLs(self, urls):
        procURLs = []
        for u in urls:
            if u not in self.urls:
                self.urls.append(u)
                procURLs.append(u)
                self.printStatus(u, 'Submitting', colors.OKBLUE)
            else:
                self.printStatus(u, 'Duplicate', colors.WARNING)
        return procURLs


    def setGlobalOptions(self):
        self.opts = {}
        if self.options.force:
            self.opts['force'] = 'true'
        else:
            self.opts['force'] = 'false'
        if self.options.noprefetch:
            self.opts['prefetch'] = 0
        else:
            self.opts['prefetch'] = 1
        if self.options.live:
            self.opts['analysistype'] = 1
        else:
            self.opts['analysistype'] = 2
        self.opts['profiles'] = self.options.profiles
        self.opts['priority'] = self.options.priority
        self.opts['timeout'] = self.options.timeout
        self.opts['application'] = "0"


    def setGlobalFilesOptions(self):
        self.opts = {}
        if self.options.force:
            self.opts['force'] = 'true'
        else:
            self.opts['force'] = 'false'
        if self.options.noprefetch:
            self.opts['prefetch'] = "0"
        else:
            self.opts['prefetch'] = "1"
        if self.options.live:
            self.opts['analysistype'] = "1"
        else:
            self.opts['analysistype'] = "2"
        self.opts['profiles'] = self.options.profiles
        self.opts['priority'] = "%s" % self.options.priority
        self.opts['timeout'] = "%s" % self.options.timeout
        self.opts['application'] = "0"


    def apiCall(self, endpoint, method='GET', **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}

        kwargs['headers']['Accept'] = 'application/json'

        if self.token:
            kwargs['headers']['X-FeApi-Token'] = self.token

        logger.debug(method)
        logger.debug(kwargs)

        response = requests.request(method, 'https://%s/wsapis/v1.1.0/%s' % (self.hostname, endpoint), verify=False, **kwargs)

        logger.debug(response.url)

        logger.debug(response.content)

        return response


    def requestStatus(self):

        for axObj in self.submissions:
            if axObj.result or axObj.status == 'Failed':
                continue

            if axObj.alertID or axObj.subID:

                if axObj.alertID:
                    axID = axObj.alertID
                else:
                    axID = axObj.subID

                response = self.apiCall('submissions/status/%s' % axID, method='GET')

                self.latestStatusResponse = response

                if response.ok:
                    axObj.setStatus(simplejson.loads(response.content))
                else:
                    axObj.processCode(response)

                logger.debug(response.text)


    def requestAlertQuery(self, filters={}):
        filters['info_level'] = self.options.infolevel

        for axObj in self.submissions:
            if axObj.result or axObj.status != 'Done':
                continue

            if axObj.alertID:
                filters['alert_id'] = axObj.alertID

            response = self.apiCall('alerts', method='GET', params=filters)

            self.latestAlertResponse = response

            if response.ok:
                axObj.setResult(simplejson.loads(response.content))
            else:
                axObj.processCode(response)

            logger.debug(response.text)


    def retrieveReportQuery(self, axObj, filters={}):
        if axObj.alertID:
            filters['id'] = axObj.alertID
            filters['report_type'] = 'alertDetailsReport'

        response = self.apiCall('reports/report', method='GET', params=filters)

        self.latestReportResponse = response
        if response.ok:
            axObj.setResult(simplejson.loads(response.content))
        else:
            axObj.processCode(response)

    
    
    
    def submitMalwareObjectQuery(self):
        self.setGlobalFilesOptions()

        for axObj in [x for x in self.submissions if x.submissionType == 'files']:
            if axObj.alertID or axObj.status == 'Failed':
                continue

            files = axObj.files
            files.append(('options', (None, simplejson.dumps(self.opts))))

            response = self.apiCall('submissions', method='POST', files=files)

            self.latestMalwareResponse = response

            if response.ok:
                axObj.setAlertID(response.json()[0])
            else:
                axObj.processCode(response)




    def submitURLQuery(self):
        self.setGlobalOptions()

        for axObj in [x for x in self.submissions if x.submissionType == 'urls']:
            if axObj.alertID or axObj.status == 'Failed':
                continue

            self.opts['urls'] = axObj.urls

            response = self.apiCall('submissions/url', method='POST', data=simplejson.dumps(self.opts), headers={'Content-Type': 'application/json'})

            self.latestURLResponse = response

            if response.ok:
                axObj.setSubmissionID(simplejson.loads(response.content))
            else:
                axObj.processCode(response)


    def unfinished(self):
        self.polls += 1

        for sub in self.submissions:
            if sub.error:
                continue
            if not sub.status:
                return True
            if sub.status == 'In Progress':
                return True

        return False


    def stdWriteFlush(self, msg):
        sys.stdout.write(msg)
        sys.stdout.flush()


    def sleepWithStatus(self):
        progress = ['/', '-', '\\', '|']
        for i in range(0,self.sleepTime * 4):
            remaining = [sub for sub in self.submissions if sub.status == 'In Progress' or (not sub.error and not sub.status)]
            if remaining:
                self.stdWriteFlush("\r%-70s [ %s ]" % ('Analysis Remaining: %d%sDuration: %d seconds' % (len(remaining),
                                                                                                         ' ' * 16,
                                                                                                         (datetime.datetime.today() - self.starTime).seconds),
                                                                                                         progress[self.progressPos % len(progress)]))
            self.progressPos += 1
            sleep(.25)


    def poll(self, maxIter=24):

        self.starTime = datetime.datetime.today()

        while self.unfinished():
            self.submitMalwareObjectQuery()
            self.submitURLQuery()
            self.requestStatus()
            self.requestAlertQuery()

            for sub in self.submissions:
                if sub.result and sub.alertID not in self.completed:
                    self.completed.append(sub.alertID)
                    yield sub

            if self.unfinished():
                if self.polls > maxIter:
                    print("\n\n%sMax iterations met before all submissions completed. Skipping...%s\n" % (colors.WARNING, colors.ENDC))
                    return
                else:
                    self.sleepWithStatus()
            else:
                print('')
        print('')


    def login(self, reauth=False):
        if not self.username:
            if self.credential and os.path.isfile(self.credential):
                cred = re.search('machine (?P<machine>\S+) login (?P<username>\S+) password (?P<password>\S+)', open(self.credential).read())
                if cred.group('machine') == self.hostname:
                    self.username = cred.group('username')
                    self.password = cred.group('password')

        if not self.token or reauth:
            response = self.apiCall('auth/login', method='POST', auth=(self.username, self.password))

            if response.ok:
                self.token = response.headers['X-FeApi-Token']
            else:
                print("Auth Error: %s" % (response.reason))
                exit()


    def logout(self):
        self.apiCall('auth/logout', method='POST')

    def __exit__(self):
        self.logout()



'''
main:  This is the main method, used for flow control
'''
def main():

    options = processArgs()

    ax = FireEyeAX(options)

    results = list(ax.poll())

    for axObj in results:
        if axObj.malicious:
            verdict = "%sMalicious%s" % (colors.FAIL, colors.ENDC)
        else:
            verdict = "%sClean%s" % (colors.OKGREEN, colors.ENDC)

        if axObj.submission:
            sub = "Submission " + axObj.submission
        elif axObj.alertID:
            sub = "Alert ID " + axObj.alertID
        else:
            sub = "Error"

        print("%-70s [ %s ]" % (sub, verdict))


'''
Runs main as long as script is executed at the command line, looks for and catches
Ctrl-C keyboard interrupts in case the python interpreter or O/S doesn't by default.
'''
if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt):
        print("^C")
        exit()

