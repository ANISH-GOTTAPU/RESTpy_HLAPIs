from ixia import Ixia

tgnObj = Ixia('127.0.0.1', clearConfig=False)

# connect_to_session API
tgnObj.connect_to_session(sessionId=1)

# load_config API
tgnObj.load_config(config_file='ixnetwork.ixncfg')

# set_chassis API
tgnObj.set_chassis(["10.39.68.149"])

# get_vport_from_ip API
tgnObj.get_vport_from_ip("20.0.0.6")

# assign_port_to_ip API
tgnObj.assign_port_to_ip("10.39.68.149/1/3", "20.0.0.6")

# connect_ports API
tgnObj.connect_ports(port_tuple=[["10.39.68.149", "1", "8"], ["10.39.68.149", "1", "7"]])

# start_traffic_by_name API
tgnObj.start_traffic_by_name("Traffic Item 1")

# get_stats API
tgnObj.get_stats() # default Flow Statistics will return
tgnObj.get_stats(csv_file=None, csv_enable_file_timestamp=False, view_name='Port CPU Statistics')

# clear_traffic_stats API
tgnObj.clear_traffic_stats()

# stop_traffic_by_name API
tgnObj.stop_traffic_by_name("Traffic Item 1")

# set_traffic_destmac API
tgnObj.set_traffic_destmac(traffic_item_name='Traffic Item 1', mac_dst='00:00:00:00:00:01')

# link_up_down API
tgnObj.link_up_down(port=["Ethernet - 001", "Ethernet - 002"], action='down')

# enable_traffic_item API
tgnObj.enable_traffic_item(traffic_item_list=['Traffic Item 1', 'Traffic Item 2'])

# disable_traffic_item API
tgnObj.disable_traffic_item(traffic_item_list=['Traffic Item 1', 'Traffic Item 2'])

# start_all_traffic API
tgnObj.start_all_traffic()

# stop_all_traffic API
tgnObj.stop_all_traffic()

# disconnect_session API
tgnObj.disconnect_session(port_list=['Ethernet - 001','Ethernet - 002'], tgn_server_type="linux")

# start_bgp API
tgnObj.start_bgp()
tgnObj.start_bgp(ports=['Ethernet - 001', 'Ethernet - 002'])
tgnObj.start_bgp(ports=['/api/v1/sessions/1/ixnetwork/vport/1', '/api/v1/sessions/1/ixnetwork/vport/2'])

# stop_bgp API
tgnObj.stop_bgp()
tgnObj.stop_bgp(ports=['Ethernet - 001', 'Ethernet - 002'])
tgnObj.stop_bgp(ports=['/api/v1/sessions/1/ixnetwork/vport/1','/api/v1/sessions/1/ixnetwork/vport/2'])

# send_arp API
tgnObj.send_arp()
tgnObj.send_arp(ports=['Ethernet - 001'])

# start_all_protocols API
tgnObj.start_all_protocols()

# stop_all_protocols API
tgnObj.stop_all_protocols()

# get_routerrange_details API
tgnObj.get_routerrange_details('/api/v1/sessions/1/ixnetwork/vport/1','bgpv6')

# get_routerange_state API
tgnObj.get_routerange_state('/api/v1/sessions/1/ixnetwork/vport/1','bgpv6')