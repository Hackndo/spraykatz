# coding: utf-8

# Author:	Romain BENTZ
# Twitter:	@hackanddo
# Based on Impacket atexec implementation by @agsolino
# https://github.com/SecureAuthCorp/impacket/blob/429f97a894d35473d478cbacff5919739ae409b4/examples/atexec.py

import time
from datetime import datetime
from core.Logs import *
from core.ParseDump import *
from core.PrintCreds import *
from core.WriteCreds import *
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import tsch, transport


class ATEXEC_DELETE:
    def __init__(self, smbConnection, username='', password='', domain='', lmhash=None, nthash=None):
        self.__smbConnection = smbConnection
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash

    def run(self, addr, osArch='64'):
        try:
            stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
            self._rpctransport = transport.DCERPCTransportFactory(stringbinding)

            if hasattr(self._rpctransport, 'set_credentials'):
                self._rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            dce = self._rpctransport.get_dce_rpc()

            dce.set_credentials(*self._rpctransport.get_credentials())
            dce.connect()
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            logging.info("%s  Deleting dumps on %s..." % (debugBlue, addr))
            command = "del C:\\SPRAY_*.dmp"

            xml = self.gen_xml(command)
            tmpName = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            tsch.hSchRpcRun(dce, '\\%s' % tmpName)
            done = False
            while not done:
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)

            time.sleep(3)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            dce.disconnect()
        finally:
            if self.__smbConnection is not None:
                self.__smbConnection.logoff()
            sys.stdout.flush()

    def gen_xml(self, command):

        return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/C {}</Arguments>
    </Exec>
  </Actions>
</Task>
""".format(command)
