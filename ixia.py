from ixnetwork_restpy import SessionAssistant
from ixnetwork_restpy.files import Files
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
import logging,time,re,datetime,csv,functools
import netaddr, ixNetwork_Error, inspect, os, types, sys
from collections import namedtuple
# logging.basicConfig(level=logging.INFO)
class IxNetError(Exception):
    """
    Default IxNet error
    """

# default frame template (see log_exceptions below)
LOG_FRAME_TPL = '  File "%s", line %i, in %s\n    %s\n'

def log_to_str(value):
    if isinstance(value, types.FrameType):
        return ["'", value.replace('\n', '\\n'), "'"].join('')
    else:
        try:
          return str(value).replace('\n', '\\n')
        except:
          return '<ERROR: CANNOT PRINT>'

def debug_log_decorator(func):
    """
    Decorator to download debug files on Ixia exception.
    :param None
    :return: None
    """
    @functools.wraps(func)
    def wrapper_decorator(*args, **kwargs):
        try:
            value = func(*args, **kwargs)
            return value
        except Exception as ex:
            frameTemplate = LOG_FRAME_TPL
            valueToString = log_to_str
            logFile = open("exception.log", 'wt')
            try:
                # log exception information first in case something fails below
                logFile.write('Exception thrown, %s: %s\n' % (type(ex), str(ex)))
                frames = inspect.getinnerframes(sys.exc_info()[2])
                for frameInfo in reversed(frames):
                    frameLocals = frameInfo[0].f_locals
                    if '__lgw_marker_local__' in frameLocals:
                        continue
                    # log the frame information
                    logFile.write(frameTemplate %
                                   (frameInfo[1], frameInfo[2], frameInfo[3], frameInfo[4][0].lstrip()))

                    # log every local variable of the frame
                    for key, value in frameLocals.items():
                        logFile.write('    %s = %s\n' % (key, valueToString(value)))

                logFile.write('\n')
            finally:
                logFile.close()
            logs = open('exception.log', 'rt').read()
            data = re.sub(re.findall('raise (.*?)Error', logs)[0], 'IxNet', logs)
            updateLog = open("exception.log", "wt")
            updateLog.write(data)
            updateLog.close()
            raise IxNetError(ex) from ex
    return wrapper_decorator

def decorator_for_class(cls):
    """
    Class Decorator to apply decorator on all the public methods of Ixia class.
    :param None
    :return: None
    """
    for name, method in inspect.getmembers(cls):
        if (not inspect.ismethod(method) and not inspect.isfunction(method)) or inspect.isbuiltin(method):
            continue
        if name.startswith("_"):
            continue
        setattr(cls, name, debug_log_decorator(method))
    return cls

@decorator_for_class
class Ixia():
    def __init__(self,apiServerIp, clearConfig):

        self.apiServerIp = apiServerIp
        self.clearConfig = clearConfig

    def connect_to_session(self, sessionId=None, sessionName=None):
        """
        Connect to an existing session on the TGN based on API Server IP (Automatically it will connect Windows/Linux/Connection Manager based on IP).

        :param sessionId: The session ID on the Linux API server or Windows Connection Mgr to connect to.
        :param sessionName: The session Name on the Linux API server
        :return: True if successful else raises exception

        :Example: connect_to_session(sessionId=1) or connect_to_session(sessionName="sessionname")
        """
        if sessionId:
            session_assistant = SessionAssistant(IpAddress=self.apiServerIp,
                                                 UserName='admin', Password='admin',
                                                 LogLevel=SessionAssistant.LOGLEVEL_INFO,
                                                 ClearConfig=self.clearConfig, SessionId=sessionId)
            if session_assistant:
                self.session = session_assistant.Session
                self.ixnetwork = session_assistant.Ixnetwork
            # else:
            #     raise ixNetwork_Error.IxiaConnectionError("Failed to connect API Server %s"%self.apiServerIp)
        elif sessionName:
            session_assistant = SessionAssistant(IpAddress=self.apiServerIp,
                                                 UserName='admin', Password='admin',
                                                 LogLevel=SessionAssistant.LOGLEVEL_INFO,
                                                 ClearConfig=self.clearConfig, SessionName=sessionName)
            if session_assistant:
                self.session = session_assistant.Session
                self.ixnetwork = session_assistant.Ixnetwork
            # else:
            #     raise ixNetwork_Error.IxiaConnectionError("Failed to connect API Server %s"%self.apiServerIp)
        else:
            session_assistant = SessionAssistant(IpAddress=self.apiServerIp,
                                                 UserName='admin', Password='admin',
                                                 LogLevel=SessionAssistant.LOGLEVEL_INFO,
                                                 ClearConfig=self.clearConfig)
            if session_assistant:
                self.session = session_assistant.Session
                self.ixnetwork = session_assistant.Ixnetwork
            # else:
            #     raise ixNetwork_Error.IxiaConnectionError("Failed to connect API Server {0}".format(self.apiServerIp))

        return True

    def set_chassis(self, chassis_ip_list):
        """
        Connect to IXIA Chassis

        :param chassis_ip_list: list of chassis' IPs to which session has to connect
        :return: True if successful

        :Example: set_chassis(["10.39.60.120"])
        """
        logging.info("Connection to the Chassis:%s" % (chassis_ip_list))
        timeout = 100
        for chassisIp in chassis_ip_list:
            self.ixnetwork.AvailableHardware.Chassis.add(Hostname=chassisIp)
            for counter in range(1, timeout+1):
                if self.ixnetwork.AvailableHardware.Chassis.find(Hostname=chassisIp).State == 'ready':
                    break
                else:
                    time.sleep(1)
                if counter == 100:
                    raise ixNetwork_Error.IxiaConnectionError('Connect Chassis: Connecting to chassis {0} failed'.format(chassisIp))
        return True

    def load_config(self, config_file=None, port_tuple=None, chassis_ip=None):
        """
        API used to load existing config file with extension .ixncfg or .json

        :param config_file: The full path including the saved config file
        :param port_tuple: [chassisIP/card/port,chassisIP/card/port,...]
        :param chassis_ip: Chassis ip
        :return: True if successful else raise Exception

        :Example: load_config(config_file='ospf_bgp_ldp_config.ixncfg', port_tuple=["10.39.60.120/1/1","10.39.60.120/1/2"])
        """

        if config_file:
            logging.info("Loading config file {0}".format(config_file))
            self.ixnetwork.LoadConfig(Files(config_file,local_file=True))
        else:
            logging.info('No config file given, attaching to existing session')
            self.ixnetwork.NewConfig()
        if port_tuple:
            chassis_list = []
            port_list = []
            for port in port_tuple:
                chassis_list_temp = port.split('/')
                port_list_temp = port.split('/')
                if len(chassis_list_temp) < 3:
                    chassis_list.append(chassis_ip)
                    port_list_temp.insert(0, chassis_ip)
                else:
                    chassis_list.append(port.split('/')[0])
                port_list.append(port_list_temp)
            chassis_list = list(set(chassis_list))
            self.set_chassis(chassis_list)
            self.connect_ports(port_list)

        return True

    def connect_ports(self, port_tuple):
        """
        Function used internally by other APIS,Assign Ports and Verify

        :param port_tuple: [[chassisIP, card, port], [chassisIP, card, port],..]
        """
        forceTakePortOwnership = True
        # Forcefully take port ownership if the portList are owned by other users.
        testPorts = []
        vportList = [vport.href for vport in self.ixnetwork.Vport.find()]
        for port in port_tuple:
            testPorts.append(dict(Arg1=port[0], Arg2=port[1], Arg3=port[2]))
        self.ixnetwork.AssignPorts(testPorts, [], vportList, forceTakePortOwnership)
        timeout = 60
        for vportObj in self.ixnetwork.Vport.find():
            for counter in range(1, timeout+1):
                if vportObj.State == 'up':
                    return "Ports are Up"
                else:
                    time.sleep(1)
                if counter == 60:
                    raise ixNetwork_Error.IxiaConnectionError('Connect Ports: Connecting to ports {0} failed'.format(port_tuple))

    def get_list_topology_name(self):
        """
        Get list of port names in config

        :return: list of ports in user readable format in the session

        :Example: get_list_topology_name()
        """
        logging.info("vport name list")
        topoNameList =[topo.Name for topo in self.ixnetwork.Topology.find()]
        return topoNameList

    def get_vport_from_ip(self, ip):
        """Given IP address, get corresponding vport

        :param ip: IPv4 addr, like '20.0.0.6'
        :returns: vport string, e.g. '/api/v1/sessions/43/ixnetwork/vport/1'
        """
        topology_list = self.get_list_topology_name()
        ethernet_list = [ethernetObj for ethernetObj in
                         self.ixnetwork.Topology.find().DeviceGroup.find().Ethernet.find()]
        for ethernet, topoName in zip(ethernet_list, topology_list):
            if ethernet.Ipv4.find():
                for ipv4Obj in ethernet.Ipv4.find():
                    if ip in ipv4Obj.Address.Values:
                        vportHref = self.ixnetwork.Topology.find(Name=topoName).Vports
                        return vportHref
            if ethernet.Ipv6.find():
                for ipv6Obj in ethernet.Ipv6.find():
                    if ip in ipv6Obj.Address.Values:
                        vportHref = self.ixnetwork.Topology.find(Name=topoName).Vports
                        return vportHref

    def start_all_protocols(self):
        """
        Start all the configured protocols in config file

        :return: True if successful else Raise Exception

        :Example: start_all_protocols()
        """
        logging.info("Starting all Protocols")
        self.ixnetwork.StartAllProtocols(Arg1='sync')
        timeout = 20
        for deviceGroupObj in self.ixnetwork.Topology.find().DeviceGroup.find():
            for counter in range(0, timeout, 2):
                if deviceGroupObj.Status == 'notStarted':
                    msg = '\nDevice Group "%s" is not started' % deviceGroupObj.Name
                    raise ixNetwork_Error.IxiaOperationException(msg)
                if counter < timeout and deviceGroupObj.Status == 'starting':
                    time.sleep(2)
                    continue
                if counter < timeout and deviceGroupObj.Status in ['started', 'mixed']:
                    break
                if counter == timeout and deviceGroupObj.Status not in ['started', 'mixed']:
                    msg = '\nDevice Group failed to come up: {0}.'.format(deviceGroupObj.href)
                    raise ixNetwork_Error.IxiaOperationException(msg)
        return True

    def stop_all_protocols(self):
        """
        Stop all the configured protocols in config file

        :return: True if successful else Raise Exception

        :Example: stop_all_protocols()
        """
        logging.info("Stopping all Protocols")
        self.ixnetwork.StopAllProtocols(Arg1='sync')
        return True

    def assign_port_to_ip(self, phy_intf, ip_addr):
        """
        Assign physical interface to the vport that has ip_addr

        :param phy_intf: e.g. '"10.39.68.149/1/3"' for chassis 10.39.68.149, card 1, port 3
        :param ip_addr: vport's preconfigured ip/mask, e.g. '20.0.0.6'
        :raises: PortConnectivityError
        :returns: assigned vport
        Example: assign_port_to_ip("10.39.68.149/1/3", "20.0.0.6")
        """
        port_tuple = [intf for intf in phy_intf.split('/')]
        chassis_ip = port_tuple[0]
        test_ports = [dict(Arg1=chassis_ip, Arg2=port_tuple[1], Arg3=port_tuple[2])]
        virtual_ports = self.ixnetwork.Vport.add()
        self.ixnetwork.AssignPorts(test_ports, [], virtual_ports, True)
        vports = self.get_vport_from_ip(ip_addr)
        for topoObj in self.ixnetwork.Topology.find():
            vportList = topoObj.Vports
            for vport in vports:
                if vport in vportList:
                    vportList.append(virtual_ports.href)
            topoObj.update(Ports=vportList)

    def regenerate_traffic(self):
        """
        Regenerate all traffic items

        :return: True else Raise Error if failed

        :Example: regenerate_traffic()
        """
        try:
            logging.info('Regenerating Traffic Items')
            if self.ixnetwork.Traffic.State == 'started':
                pass
            else:
                trafficItem = self.ixnetwork.Traffic.TrafficItem.find()
                trafficItem.Generate()
        except:
            raise ixNetwork_Error.IxiaConfigException("Failed to Re-Generate Traffic")

        return True

    def start_traffic_by_name(self, traffic_item_name):
        """
        Start Traffic based on traffic name.
        :param traffic_item_name: Traffic stream name
        :return: True
        """
        self.start_all_protocols()
        if self.ixnetwork.Traffic.TrafficItem.find(Name='^' + traffic_item_name + '$').State in ['stopped','stoppedWaitingForStats','unapplied']:
            self.ixnetwork.Traffic.Apply()
            globals = self.ixnetwork.Globals
            apperrors = globals.AppErrors.find()
            for error in apperrors.Error.find():
                if "One or more destination MACs or VPNs are invalid" in error.Description:
                    raise ixNetwork_Error.IxiaOperationException("Failed to apply traffic as packets are not generated properly")
            self.ixnetwork.Traffic.TrafficItem.find(Name='^' + traffic_item_name + '$').StartStatelessTraffic()
        timeout = 30
        for counter in range(1, timeout+1):
            if self.ixnetwork.Traffic.TrafficItem.find(Name='^' + traffic_item_name + '$').State in ['started', 'startedWaitingForStats', 'startedWaitingForStreams']:
                return True
            else:
                time.sleep(1)
            if counter == 30:
                raise ixNetwork_Error.IxiaOperationException('Failed to start Traffic Item : {0}'.format(traffic_item_name))

    def stop_traffic_by_name(self, traffic_item_name):
        """
        Start Traffic based on traffic name.
        :param traffic_item_name: Traffic stream name
        :return: True
        """
        self.ixnetwork.Traffic.TrafficItem.find(Name='^' + traffic_item_name + '$').StopStatelessTraffic()
        return True

    def start_all_traffic(self):
        """
        Start all the traffic streams
        :return: True
        """
        self.start_all_protocols()
        if self.ixnetwork.Traffic.State in ['stopped','stoppedWaitingForStats','unapplied']:
            self.regenerate_traffic()
            self.ixnetwork.Traffic.Apply()
            self.ixnetwork.Traffic.Start()
            timeout = 30
            for counter in range(1, timeout + 1):
                if self.ixnetwork.Traffic.State in ['started', 'startedWaitingForStats', 'startedWaitingForStreams']:
                    return True
                else:
                    time.sleep(1)
                if counter == 30:
                    raise ixNetwork_Error.IxiaOperationException('Failed to start Traffic Streams')
        else:
            return 'Traffic Streams already started'

    def stop_all_traffic(self):
        """
        Start all the traffic streams
        :return: True
        """
        self.ixnetwork.Traffic.Stop()
        return True

    def _portname_location_mapping(self):
        """
        Internal API used by get_stats to map portname with location

        :return:
        """
        portnameLocationDict = {}
        for vport in self.ixnetwork.Vport.find():
            try:
                assignedChassis = vport.AssignedTo.split(":")[0]
                assignedCard = vport.AssignedTo.split(":")[1]
                assignedPort = vport.AssignedTo.split(":")[2]
                portnameLocationDict[vport.Name] = "//"+assignedChassis+"/"+assignedCard+"/"+assignedPort
            except:
                pass

        return portnameLocationDict

    def _change_to_int(self,value):
        """
        internal API used by get_stats to change type
        :param value: value whose datatype to be updated
        :return:
        """

        if value == '' or value == 'N/A':
            value = 0
        elif value != '' and value != 'N/A':
            value = int(float(value))

        return value

    def get_stats(self, csv_file=None, csv_enable_file_timestamp=False,
                  view_name='Flow Statistics'):
        """
        Get flow statistics and save it in a csv file

        :param csv_file: None or <filename.csv>.
               None will not create a CSV file.
               Provide a <filename>.csv to record all stats to a CSV file.
               Example: getStats(csv_file='Flow_Statistics.csv')
        :param csv_enable_file_timestamp: True or False. If True, timestamp
                will be appended to the filename.
        :param view_name: view_name options (case sensitive):
                "Port Statistics",
                "Tx-Rx Frame Rate Statistics",
                "Port CPU Statistics",
                "Global Protocol Statistics",
                "Protocols Summary",
                "Port Summary",
                "OSPFv2-RTR Drill Down",
                "OSPFv2-RTR Per Port",
                "IPv4 Drill Down",
                "L2-L3 Test Summary Statistics",
                "Flow Statistics",
                "Traffic Item Statistics", \n
                Note: Not all of the view_names are listed here. You have to get the
                exact names from the IxNetwork GUI in statistics based on your
                protocol(s)
        :return:  A dictionary of all the stats: stat_dict[rowNumber][columnName]== stat_value

        :Example: get_stats() \n
                  get_stats(csv_file=None, csv_enable_file_timestamp=False,view_name='Port CPU Statistics') \n
                  get_stats(csv_file="TrafficItemStatistics.csv", csv_enable_file_timestamp=False,view_name='Traffic Item Statistics')
        """
        logging.info('\ngetStats: %s' % (view_name))
        if csv_file:
            try:
                statsSummary = StatViewAssistant(self.ixnetwork, view_name)
            except:
                logging.error('getStats: Failed to get stats values')

            csv_filename = csv_file.replace(' ', '_')
            if csv_enable_file_timestamp:
                timestamp = datetime.datetime.now().strftime('%H%M%S')
                if '.' in csv_filename:
                    csv_filename_temp = csv_filename.split('.')[0]
                    csv_filename_extension = csv_filename.split('.')[1]
                    csv_filename = csv_filename_temp + '_' + timestamp + '.' + \
                                   csv_filename_extension
                else:
                    csv_filename = csv_filename + '_' + timestamp

            csv_file = open(csv_filename, 'w')
            csv_write_obj = csv.writer(csv_file)
            # Get the stat column names
            columnCaptions = statsSummary.ColumnHeaders
            if csv_file != None:
                csv_write_obj.writerow(columnCaptions)
                for rowNumber, stat in enumerate(statsSummary.Rows):
                    rowStats = stat.RawData
                for row in rowStats:
                    csv_write_obj.writerow(row)
            return statsSummary, csv_file.name
        else:
            portNameLocationMapping = self._portname_location_mapping()
            TrafficItemStats = StatViewAssistant(self.ixnetwork, view_name)
            trafficItemStatsDict = {}
            columnCaptions = TrafficItemStats.ColumnHeaders

            for rowNumber, stat in enumerate(TrafficItemStats.Rows):
                statsDict = {}
                for column in columnCaptions:
                    statsDict[column] = stat[column]
                trafficItemStatsDict[rowNumber + 1] = statsDict
            for key, value in trafficItemStatsDict.items():
                if 'Packet Loss Duration (ms)' in value:
                    if value['Packet Loss Duration (ms)'] == '':
                        value['Packet Loss Duration (ms)'] = 0
                    else:
                        value['Packet Loss Duration (ms)'] = int(float(value['Packet Loss Duration (ms)']))
                if 'Tx Frames' in value:
                    value['Tx Frames'] = int(float(value['Tx Frames']))
                if 'Rx Frames' in value:
                    value['Rx Frames'] = int(float(value['Rx Frames']))
                if 'Tx Rate (Bps)' in value:
                    value['Tx Rate (Bps)'] = self._change_to_int(value['Tx Rate (Bps)'])
                if 'Rx Rate (Bps)' in value:
                    value['Rx Rate (Bps)'] = self._change_to_int(value['Rx Rate (Bps)'])
                if 'Tx Rate (bps)' in value:
                    value['Tx Rate (bps)'] = self._change_to_int(value['Tx Rate (bps)'])
                if 'Rx Rate (bps)' in value:
                    value['Rx Rate (bps)'] = self._change_to_int(value['Rx Rate (bps)'])
                if 'Rx L1 Rate (bps)' in value:
                    value['Rx L1 Rate (bps)'] = self._change_to_int(value['Rx L1 Rate (bps)'])
                if 'Tx L1 Rate (bps)' in value:
                    value['Tx L1 Rate (bps)'] = self._change_to_int(value['Tx L1 Rate (bps)'])
                if 'Loss %' in value and value['Loss %'] == '':
                    value['Loss %'] = '0.00'
                if value.get("IPv4 :Source Address", '') != '':
                    value['IP :Source Address'] = value.pop('IPv4 :Source Address')
                if value.get("IPv4 :Destination Address", '') != '':
                    value['IP :Destination Address'] = value.pop('IPv4 :Destination Address')
                if value.get("IPv6 :Source Address", '') != '':
                    value['IP :Source Address'] = value.pop('IPv6 :Source Address')
                if value.get("IPv6 :Destination Address", '') != '':
                    value['IP :Destination Address'] = value.pop('IPv6 :Destination Address')
                if 'Tx Port' in value:
                    try:
                        value['Tx Port Location'] = portNameLocationMapping[value['Tx Port']]
                    except:
                        pass
                if 'Rx Port' in value:
                    try:
                        value['Rx Port Location'] = portNameLocationMapping[value['Rx Port']]
                    except:
                        pass

            return trafficItemStatsDict

    def clear_traffic_stats(self):
        """
        Clears the traffic statistics on the chassis

        :return: True if success, false if error

        :Example: clear_traffic_stats()
        """
        logging.info("Clearing Stats")
        try:
            self.ixnetwork.ClearStats(Arg1=["waitForTrafficStatsRefresh"])
        except:
            pass
        logging.info("Traffic Stats Cleared")
        return True

    def _change_mac_format(self,inputMac):
        """
        Internal function to change MAC address format

        :param inputMac: MAC Address in any format
                        EX:'008a.9695.748c'
        :return: MAC Address in actual format
                OutputMac: '00:8a:96:95:74:8c'
        """
        outputMac = netaddr.EUI(inputMac)
        outputMac.dialect = netaddr.mac_unix_expanded
        return str(outputMac)

    def set_traffic_destmac(self, traffic_item_name=None, mac_dst='00:00:00:00:00:01', mac_dst_count=1, mac_dst_mode=None,
                           mac_dst_step='00:00:00:00:00:01',
                           mac_dst_mask='FF:FF:FF:FF:FF:FF',
                           mac_dst_seed=1,):
        """
        API used to change MAC Address on Traffic Item/Stream

        :param traffic_item_name: The traffic item name
        :param endpoint_name: The endpoint name
        :param mac_dst_mode: The mac destination mode
        :param mac_dst: The mac destination address
        :param mac_dst_count: The mac destination count
        :param mac_dst_step: The mac destination step
        :param mac_dst_mask: The mac destination mask
        :param mac_dst_seed: The mac destination seed
        :param mac_src_mode: The mac source mode
        :param mac_src: The mac source address
        :param mac_src_count: The mac source count
        :param mac_src_step: The mac source step
        :param mac_src_mask: The mask source mask
        :param mac_src_seed: The mask source seed
        :return: True on success else raises exception

        :Example: set_traffic_destmac(traffic_item_name="Traffic Item 4")
        """
        logging.info("Changing Mac Parameters for Traffic Item/Items")
        mac_dst = self._change_mac_format(mac_dst)
        mac_dst_step = self._change_mac_format(mac_dst_step)
        mac_dst_mask = self._change_mac_format(mac_dst_mask)
        if isinstance(traffic_item_name,str):
            trafficItemNameList = [traffic_item_name]
        elif isinstance(traffic_item_name,list):
            trafficItemNameList = traffic_item_name
        else:
            trafficItemNameList = [trafficObj.Name for trafficObj in self.ixnetwork.Traffic.TrafficItem.find()]

        for trafficItemName in trafficItemNameList:
            trafficItemName = trafficItemName.replace('+', '\+').replace('*', '\*')
            for stack in self.ixnetwork.Traffic.TrafficItem.find(Name='^'+trafficItemName+'$').ConfigElement.find().Stack.find():
                fieldNames = [fieldObj.DisplayName for fieldObj in stack[0].Field.find()]
                for fieldName in fieldNames:
                    if fieldName == "Destination MAC Address":
                        field = stack[0].Field.find(DisplayName=fieldName)
                        if mac_dst_mode:
                            field.ValueType, field.FieldValue, field.CountValue, field.StartValue, field.StepValue, field.RandomMask, field.Seed = mac_dst_mode, \
                                                                                        mac_dst,mac_dst_count,mac_dst,mac_dst_step,mac_dst_mask,mac_dst_seed
                        else:
                            field.ValueType, field.FieldValue, field.CountValue, field.StartValue, field.StepValue, field.RandomMask, field.Seed = mac_dst_mode, \
                                                                                    mac_dst, mac_dst_count, mac_dst, mac_dst_step, mac_dst_mask, mac_dst_seed

        logging.info("Mac updated in Traffic Items")
        return True

    def link_up_down(self, port, action='up'):
        """
        Flap a port Up and Down

        :param port: list of port names\n
                Example : port = ['10.30.20.140/1/5','10.30.20.140/1/6']\n
                Example : port = ['Ethernet 01' , Ethernet 02']
        :param action: CHOICES up, down
        :return: True

        :Example: link_up_down(port=["Ethernet - 001", "Ethernet - 002"], action='down')
        """
        logging.info("Simulation Link :%s" % (action))
        action = action.lower()
        for eachPort in port:
            if (re.search('\d+.\d+.\d+.\d+/\d+/\d+', eachPort)):
                eachPort = eachPort.replace("/", ":")
                for vport in self.ixnetwork.Vport.find(AssignedTo = eachPort):
                    vport.LinkUpDn(action)
                    time.sleep(30)
                for vport in self.ixnetwork.Vport.find(AssignedTo=eachPort):
                    if vport.State != action:
                        msg = 'Port "%s" Link "%s" Simulatin not Successful' % (eachPort, action)
                        logging.error(msg)

            for vport in self.ixnetwork.Vport.find(Name=eachPort):
                vport.LinkUpDn(action)
                time.sleep(30)
            for vport in self.ixnetwork.Vport.find(Name=eachPort):
                if vport.State != action:
                    msg = 'Port "%s" Link "%s" Simulation Failed' % (eachPort,action)
                    logging.error(msg)
        return True

    def enable_traffic_item(self, traffic_item_list=None):
        """
        Enable the given traffic items in the list, if None given enable all the traffic items

        :param traffic_item_list: list of traffic items to be enabled. if None, enable all
        :return: True if successful else raise Exception

        :Example: enable_traffic_item(traffic_item_list=['Traffic Item 1', 'Traffic Item 2'])
        """

        logging.info("Enabling Traffic Item/Items")
        if traffic_item_list:
            if isinstance(traffic_item_list, list):
                try:
                    for trafficName in traffic_item_list:
                        trafficName = trafficName.replace('+', '\+').replace('*', '\*')
                        self.ixnetwork.Traffic.TrafficItem.find(Name='^'+trafficName+'$').Enabled = True
                except:
                    raise ixNetwork_Error.IxiaConfigException("Not able to find the TrafficItem to Enable")
            if isinstance(traffic_item_list, str):
                try:
                    self.ixnetwork.Traffic.TrafficItem.find(Name='^'+traffic_item_list+'$').Enabled = True
                except:
                    raise ixNetwork_Error.IxiaConfigException("Not able to find the TrafficItem to Enable")
        else:
            try:
                for trafficItem in self.ixnetwork.Traffic.TrafficItem.find():
                    trafficItem.Enabled = True
            except:
                raise ixNetwork_Error.IxiaConfigException("Failed to enable TrafficItem")
        logging.info("Traffic Item/Items enabled Successfully")
        return True

    def disable_traffic_item(self, traffic_item_list=None):
        """
        Disable the given traffic items in the list, if no traffic
        items provided, then disable all traffic items instead.

        :param traffic_item_list: (list) list of traffic items to be disabled. if None, disable all
        :return: True if successful else raise exception

        :Example: disable_traffic_item(traffic_item_list=['Traffic Item 1', 'Traffic Item 2'])
        """
        logging.info("Disabling Traffic Item/Items")
        if traffic_item_list:
            if isinstance(traffic_item_list, list):
                try:
                    for trafficName in traffic_item_list:
                        trafficName = trafficName.replace('+', '\+').replace('*', '\*')
                        self.ixnetwork.Traffic.TrafficItem.find(Name='^'+trafficName+'$').Enabled = False
                except:
                    raise ixNetwork_Error.IxiaConfigException("Not able to find the TrafficItem to disable")
            if isinstance(traffic_item_list, str):
                try:
                    self.ixnetwork.Traffic.TrafficItem.find(Name='^'+traffic_item_list+'$').Enabled = False
                except:
                    raise ixNetwork_Error.IxiaConfigException("Not able to find the TrafficItem to disable")
        else:
            try:
                for trafficItem in self.ixnetwork.Traffic.TrafficItem.find():
                    trafficItem.Enabled = False
            except:
                raise ixNetwork_Error.IxiaConfigException("Failed to disable TrafficItem")
        logging.info("Traffic Item/Items Disabled Successfully")
        return True

    def release_ports(self, port_list=None):
        """
        Release ports

        :param port_list: list of port names\n
               port_list can be port_list = ['10.30.20.140/1/5','10.30.20.140/1/6']
               port_list = ['Ethernet 01' , Ethernet 02']\n
               port_list = [[ixChassisIp, 1, 2], [ixChassisIp, 1, 3], ...]
        :return: True

        :Example: release_ports(port_list=['10.30.20.140/1/5','10.30.20.140/1/6'])
        """
        logging.info("Releasing Ports")
        if port_list is None:
            try:
                ports = self.ixnetwork.Vport.find()
                ports.ResetPortCpu()
                time.sleep(5)
                ports.ReleasePort()
            except:
                pass
        else:
            vportNames = []
            for port in port_list:
                regexString = ''
                if isinstance(port, list):
                    # Construct the regex string format = '(1.1.1.1:2:3)'
                    regexString = regexString + '(' + str(port[0]) + ':' + str(port[1]) + ':' + str(port[2]) + ')'
                elif isinstance(port, str):
                    if '.' in port:
                        regexString = port.replace('/',':')
                    else:
                        try:
                            regexString = self.ixnetwork.Vport.find(Name=port).AssignedTo
                        except:
                            raise ixNetwork_Error.IxiaConfigException("Port not configured or Failed to release")
                vport = self.ixnetwork.Vport.find(AssignedTo=regexString)
                if vport:
                    vportNames.append(vport.Name)
                    logging.info('\nReleasing port: {0}:{1}'.format(port, vport.href))
                    vport.ReleasePort()
            for vport in self.ixnetwork.Vport.find():
                if vport.ConnectionStatus != 'Port Released':
                    msg = 'Release Port "%s" not Successful' % (vport.Name)
                    raise ixNetwork_Error.IxiaOperationException(msg)
        return True

    def disconnect_session(self, port_list=None, tgn_server_type="windows"):
        """
        Release the ports and delete the session.

        :param port_list: (list): format = [[(str(chassisIp), str(slotNumber), str(portNumber)]] \n
                Example: [ ['192.168.70.10', '1', '1'] ] \n
                Example: [ ['192.168.70.10', '1', '1'], ['192.168.70.10', '2', '1'] ]
        :param tgn_server_type: IxNetwork API Server windows/linux
        :return: True on success, exception on failure

        :Example: disconnect_session(port_list=['Ethernet - 001','Ethernet - 002'])
        """
        logging.info("Disconnecting TGN Session")
        if port_list:
            self.release_ports(port_list)
            results = True
        else:
            self.release_ports()
            results = True

        # If OS is linux, delete the session
        if tgn_server_type == 'linux':
            self.session.remove()
            results = True
        return results

    def _get_vport_names(self, portHandleList):
        """
        Return list of Vport names by using vport handles
        :param portHandleList:
        :return: list of vport names
        """
        portNames = []
        if portHandleList:
            for portHandle in portHandleList:
                if '/api' in portHandle:
                    for vportObj in self.ixnetwork.Vport.find():
                        if vportObj.href == portHandle:
                            portNames.append(vportObj.Name)
                else:
                    portNames.append(portHandle)
            if portNames:
                return portNames
            else:
                raise ixNetwork_Error.IxiaConfigException("Ports not available, please send port details")
        else:
            return None
        
    def send_arp(self, ports=None):
        """
        Send arp based on port list, In NGPF ARP is default once IPV4 stack is up, so no need to start_arp again

        :param ports: list of vport names or vport handles
        :return: True

        :Example: start_arp()
        """
        portNames = self._get_vport_names(ports)
        ipTypes=['Ipv4', 'Ipv6']
        if portNames:
            for portname in portNames:
                vport = self.ixnetwork.Vport.find(Name='^'+portname+'$')
                for topology in self.ixnetwork.Topology.find():
                    if vport.href in topology.Vports:
                        for ipType in ipTypes:
                            try:
                                for ipObj in eval('topology.DeviceGroup.find().Ethernet.find().'+ipType+'.find()'):
                                    objCount = ipObj.Count
                                    objCountList = [device for device in range(1, objCount + 1)]
                                    if ipType == "Ipv4":
                                        ipObj.SendArp(SessionIndices=objCountList)
                                    else:
                                        ipObj.SendNs(SessionIndices=objCountList)
                            except:
                                pass
        else:
            for ipType in ipTypes:
                try:
                    for ipObj in eval('self.ixnetwork.Topology.find().DeviceGroup.find().Ethernet.find().'+ipType+'.find()'):
                        objCount = ipObj.Count
                        objCountList = [device for device in range(1, objCount + 1)]
                        if ipType == "Ipv4":
                            ipObj.SendArp(SessionIndices=objCountList)
                        else:
                            ipObj.SendNs(SessionIndices=objCountList)
                except:
                    pass
        return True

    def start_bgp(self, ports=None):
        """
        Start BGP protocol.
        :param ports: list of vport names or vport handles
        :return: True
        """
        portNames = self._get_vport_names(ports)
        ipTypes = ['v4', 'v6']
        if portNames:
            for portname in portNames:
                vport = self.ixnetwork.Vport.find(Name='^' + portname + '$')
                for topology in self.ixnetwork.Topology.find():
                    if vport.href in topology.Vports:
                        for ipType in ipTypes:
                            try:
                                eval('topology.DeviceGroup.find().Ethernet.find().Ip'+ ipType +'.find().BgpIp'+ipType+'Peer.find().Start(None)')
                            except:
                                pass
        else:
            for ipType in ipTypes:
                try:
                    eval('self.ixnetwork.Topology.find().DeviceGroup.find().Ethernet.find().Ip' + ipType + '.find().BgpIp' + ipType + 'Peer.find().Start(None)')
                except:
                    pass
        return True

    def stop_bgp(self, ports=None):
        """
        Stop BGP protocol.
        :param ports: list of vport names or vport handles
        :return: True
        """
        portNames = self._get_vport_names(ports)
        ipTypes = ['v4', 'v6']
        if portNames:
            for portname in portNames:
                vport = self.ixnetwork.Vport.find(Name='^' + portname + '$')
                for topology in self.ixnetwork.Topology.find():
                    if vport.href in topology.Vports:
                        for ipType in ipTypes:
                            try:
                                eval('topology.DeviceGroup.find().Ethernet.find().Ip'+ ipType +'.find().BgpIp'+ipType+'Peer.find().Stop(None)')
                            except:
                                pass
        else:
            for ipType in ipTypes:
                try:
                    eval('self.ixnetwork.Topology.find().DeviceGroup.find().Ethernet.find().Ip' + ipType + '.find().BgpIp' + ipType + 'Peer.find().Stop(None)')
                except:
                    pass
        return True

    def _get_routeRanges_attr(self, protocol, ipPrefixPool, routePropertyObj, routeRange):
        """
        Get OSPF Route Ranges Attribute values
        :param ipv4PrefixPool:
        :param routePropertyObj:
        :param routeRange:
        :return:
        """
        if protocol == "ospf" or protocol == "ospfv3":
            firstRoute = (ipPrefixPool.NetworkAddress.Values)[0]
            stepvalue = ipPrefixPool.PrefixAddrStep
            number_of_routes = ipPrefixPool.NumberOfAddressesAsy
            addressFamily = ipPrefixPool.NetworkAddress.Values
            allRoutes = ipPrefixPool.LastNetworkAddress
            metric = routePropertyObj.Metric
            origin = routePropertyObj.RouteOrigin
            routerange = routeRange(addressFamily, routePropertyObj.Active, firstRoute, stepvalue, number_of_routes, metric, origin, allRoutes)
            return routerange
        if protocol == "bgp" or protocol == "bgpv6":
            firstRoute = (ipPrefixPool.NetworkAddress.Values)[0]
            stepvalue = ipPrefixPool.PrefixAddrStep
            number_of_routes = ipPrefixPool.NumberOfAddressesAsy
            allRoutes = ipPrefixPool.LastNetworkAddress
            ipType = routePropertyObj.NextHopIPType
            origin = routePropertyObj.Origin
            originId = routePropertyObj.OriginatorId
            fromPacking = routePropertyObj.PackingFrom
            toPacking = routePropertyObj.PackingTo
            routerange = routeRange(routePropertyObj.Active, ipType, firstRoute, number_of_routes, fromPacking, toPacking, stepvalue, originId, origin, allRoutes)
            return routerange

    def _get_protocol_propertyObj(self, protocol):
        """
        Get protocol Property Object name.
        :param protocol:
        :return:
        """
        OspfRouteRange = namedtuple(
            "OspfRouteRange",
            ["address_family", "enabled", "first_route", "step", "metric", "number_of_routes", "origin", "all_routes"]
        )
        Ospfv3RouteRange = namedtuple(
            "Ospfv3RouteRange",
            ["address_family", "enabled", "first_route", "step", "metric", "number_of_routes", "origin", "all_routes"]
        )
        BgpRouteRange = namedtuple(
            "BgpRouteRange",
            ["enabled", "ip_type", "first_route", "number_of_routes", "from_packing", "to_packing", "step",
             "originator_id", "origin_protocol", "all_routes"]
        )
        Bgpv6RouteRange = namedtuple("Bgpv6RouteRange",
                                     ["enabled", "ip_type", "first_route", "number_of_routes", "from_packing",
                                      "to_packing", "step",
                                      "originator_id", "origin_protocol", "all_routes"])
        IsisRouteRange = namedtuple("IsisRouteRange", [])
        LdpRouteRange = namedtuple("LdpRouteRange", [])
        Ldpv6RouteRange = namedtuple("Ldpv6RouteRange", [])
        protocolDict = {
            'bgp' : {
                'propertyObj': 'BgpIPRoute', 'version': 'v4', 'routeRange': BgpRouteRange
            },
            'bgpv6': {
                'propertyObj': 'BgpV6IPRoute', 'version': 'v6', 'routeRange': Bgpv6RouteRange
            },
            'ospf': {
                'propertyObj': 'BgpV6IPRoute', 'version': 'v4', 'routeRange': OspfRouteRange
            },
            'ospfv3': {
                'propertyObj': 'Ospfv3Route', 'version': 'v6', 'routeRange': Ospfv3RouteRange
            },
            'ldp': {
                'propertyObj': 'LdpFEC', 'version': 'v4', 'routeRange': LdpRouteRange
            },
            'ldpv6': {
                'propertyObj': 'LdpIpv6FEC', 'version': 'v6', 'routeRange': Ldpv6RouteRange
            },
            'isis': {
                'propertyObj': 'IsisL3Route', 'version': 'v4', 'routeRange': IsisRouteRange
            },
            'isisv6': {
                'propertyObj': 'IsisL3Route', 'version': 'v6', 'routeRange': IsisRouteRange
            }
        }
        if protocol.lower() in protocolDict:
            propertyObj = protocolDict[protocol.lower()]['propertyObj']
            version = protocolDict[protocol.lower()]['version']
            routeRange = protocolDict[protocol.lower()]['routeRange']
        else:
            raise ixNetwork_Error.IxiaConfigException("Please send a valid protocol name")
        return [propertyObj,version,routeRange]

    def get_routerrange_details(self, port, protocol):
        """
        Get all routers and route ranges advertised.
        :param vport: vport name or handle
        :param protocol: protocol name
        :return example: {('router1::ixiastr', '50.1.1.1'):
            {('routerange2::ixiastr', '13.1.1.1'): namedtuple<OspfRouteRange>,
            ('routerange1::ixiastr', '12.1.1.1'): namedtuple<OspfRouteRange>}}

        """
        portNames = self._get_vport_names([port])
        routeProperty = self._get_protocol_propertyObj(protocol)
        propertyObj = routeProperty[0]
        version = routeProperty[1]
        routeRange = routeProperty[2]
        routeRanges = {}
        if portNames:
            for portname in portNames:
                vport = self.ixnetwork.Vport.find(Name='^' + portname + '$')
                for topology in self.ixnetwork.Topology.find():
                    if vport.href in topology.Vports:
                        for deviceObj in topology.DeviceGroup.find():
                            for networkObj in deviceObj.NetworkGroup.find():
                                try:
                                    if eval('networkObj.Ip'+version+'PrefixPools.find().'+propertyObj+'Property.find()'):
                                        for ipPrefixPool in eval('networkObj.Ip'+version+'PrefixPools.find()'):
                                            firstRoute = (ipPrefixPool.NetworkAddress.Values)[0]
                                            for routePropertyObj in eval('ipPrefixPool.'+propertyObj+'Property.find()'):
                                                routerange= self._get_routeRanges_attr(protocol.lower(), ipPrefixPool, routePropertyObj, routeRange)
                                                routeRanges[networkObj.Name, (deviceObj.RouterData.find().RouterId.Values)[0]] = {(routePropertyObj.Name,firstRoute):routerange}
                                except:
                                    pass
        if routeRanges:
            return routeRanges
        else:
            raise ixNetwork_Error.IxiaConfigException("Route ranges not available on this {0} port for the {1} protocol".format(port,protocol))

    def get_routerange_state(self, vport_objref, proto_name="ospf"):
        """
        Get Route Range state.
        :param vport_objref:
        :param proto_name:
        :return:
        """
        portNames = self._get_vport_names([vport_objref])
        routeProperty = self._get_protocol_propertyObj(proto_name)
        propertyObj = routeProperty[0]
        version = routeProperty[1]
        routeRangesState = []
        if portNames:
            for portname in portNames:
                vport = self.ixnetwork.Vport.find(Name='^' + portname + '$')
                for topology in self.ixnetwork.Topology.find():
                    if vport.href in topology.Vports:
                        for deviceObj in topology.DeviceGroup.find():
                            for networkObj in deviceObj.NetworkGroup.find():
                                try:
                                    if eval('networkObj.Ip' + version + 'PrefixPools.find().' + propertyObj + 'Property.find()'):
                                        for ipPrefixPool in eval('networkObj.Ip' + version + 'PrefixPools.find()'):
                                            for routePropertyObj in eval('ipPrefixPool.' + propertyObj + 'Property.find()'):
                                                state = routePropertyObj.Active
                                                routeRangesState.append(state)
                                except:
                                    pass
        if routeRangesState:
            return routeRangesState
        else:
            raise ixNetwork_Error.IxiaConfigException(
                "Route ranges not available on this {0} port for the {1} protocol".format(vport_objref, proto_name))

