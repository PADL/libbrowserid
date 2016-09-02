# P2P group formation test cases
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import time
import threading
import Queue
import os

import hostapd
import hwsim_utils
import utils
from utils import HwsimSkip
from wpasupplicant import WpaSupplicant

def check_grpform_results(i_res, r_res):
    if i_res['result'] != 'success' or r_res['result'] != 'success':
        raise Exception("Failed group formation")
    if i_res['ssid'] != r_res['ssid']:
        raise Exception("SSID mismatch")
    if i_res['freq'] != r_res['freq']:
        raise Exception("freq mismatch")
    if 'go_neg_freq' in r_res and i_res['go_neg_freq'] != r_res['go_neg_freq']:
        raise Exception("go_neg_freq mismatch")
    if i_res['freq'] != i_res['go_neg_freq']:
        raise Exception("freq/go_neg_freq mismatch")
    if i_res['role'] != i_res['go_neg_role']:
        raise Exception("role/go_neg_role mismatch")
    if 'go_neg_role' in r_res and r_res['role'] != r_res['go_neg_role']:
        raise Exception("role/go_neg_role mismatch")
    if i_res['go_dev_addr'] != r_res['go_dev_addr']:
        raise Exception("GO Device Address mismatch")

def go_neg_init(i_dev, r_dev, pin, i_method, i_intent, res):
    logger.debug("Initiate GO Negotiation from i_dev")
    try:
        i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), pin, i_method, timeout=20, go_intent=i_intent)
        logger.debug("i_res: " + str(i_res))
    except Exception, e:
        i_res = None
        logger.info("go_neg_init thread caught an exception from p2p_go_neg_init: " + str(e))
    res.put(i_res)

def go_neg_pin(i_dev, r_dev, i_intent=None, r_intent=None, i_method='enter', r_method='display'):
    r_dev.p2p_listen()
    i_dev.p2p_listen()
    pin = r_dev.wps_read_pin()
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.dump_monitor()
    res = Queue.Queue()
    t = threading.Thread(target=go_neg_init, args=(i_dev, r_dev, pin, i_method, i_intent, res))
    t.start()
    logger.debug("Wait for GO Negotiation Request on r_dev")
    ev = r_dev.wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation timed out")
    r_dev.dump_monitor()
    logger.debug("Re-initiate GO Negotiation from r_dev")
    r_res = r_dev.p2p_go_neg_init(i_dev.p2p_dev_addr(), pin, r_method, go_intent=r_intent, timeout=20)
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    t.join()
    i_res = res.get()
    if i_res is None:
        raise Exception("go_neg_init thread failed")
    logger.debug("i_res: " + str(i_res))
    logger.info("Group formed")
    hwsim_utils.test_connectivity_p2p(r_dev, i_dev)
    i_dev.dump_monitor()
    return [i_res, r_res]

def go_neg_pin_authorized(i_dev, r_dev, i_intent=None, r_intent=None, expect_failure=False, i_go_neg_status=None, i_method='enter', r_method='display', test_data=True, i_freq=None, r_freq=None):
    i_dev.p2p_listen()
    pin = r_dev.wps_read_pin()
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.p2p_go_neg_auth(i_dev.p2p_dev_addr(), pin, r_method, go_intent=r_intent, freq=r_freq)
    r_dev.p2p_listen()
    i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), pin, i_method, timeout=20, go_intent=i_intent, expect_failure=expect_failure, freq=i_freq)
    r_res = r_dev.p2p_go_neg_auth_result(expect_failure=expect_failure)
    logger.debug("i_res: " + str(i_res))
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    i_dev.dump_monitor()
    if i_go_neg_status:
        if i_res['result'] != 'go-neg-failed':
            raise Exception("Expected GO Negotiation failure not reported")
        if i_res['status'] != i_go_neg_status:
            raise Exception("Expected GO Negotiation status not seen")
    if expect_failure:
        return
    logger.info("Group formed")
    if test_data:
        hwsim_utils.test_connectivity_p2p(r_dev, i_dev)
    return [i_res, r_res]

def go_neg_init_pbc(i_dev, r_dev, i_intent, res, freq, provdisc):
    logger.debug("Initiate GO Negotiation from i_dev")
    try:
        i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), None, "pbc",
                                      timeout=20, go_intent=i_intent, freq=freq,
                                      provdisc=provdisc)
        logger.debug("i_res: " + str(i_res))
    except Exception, e:
        i_res = None
        logger.info("go_neg_init_pbc thread caught an exception from p2p_go_neg_init: " + str(e))
    res.put(i_res)

def go_neg_pbc(i_dev, r_dev, i_intent=None, r_intent=None, i_freq=None, r_freq=None, provdisc=False, r_listen=False):
    if r_listen:
        r_dev.p2p_listen()
    else:
        r_dev.p2p_find(social=True)
    i_dev.p2p_find(social=True)
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.dump_monitor()
    res = Queue.Queue()
    t = threading.Thread(target=go_neg_init_pbc, args=(i_dev, r_dev, i_intent, res, i_freq, provdisc))
    t.start()
    logger.debug("Wait for GO Negotiation Request on r_dev")
    ev = r_dev.wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation timed out")
    r_dev.dump_monitor()
    # Allow some time for the GO Neg Resp to go out before initializing new
    # GO Negotiation.
    time.sleep(0.2)
    logger.debug("Re-initiate GO Negotiation from r_dev")
    r_res = r_dev.p2p_go_neg_init(i_dev.p2p_dev_addr(), None, "pbc",
                                  go_intent=r_intent, timeout=20, freq=r_freq)
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    t.join()
    i_res = res.get()
    if i_res is None:
        raise Exception("go_neg_init_pbc thread failed")
    logger.debug("i_res: " + str(i_res))
    logger.info("Group formed")
    hwsim_utils.test_connectivity_p2p(r_dev, i_dev)
    i_dev.dump_monitor()
    return [i_res, r_res]

def go_neg_pbc_authorized(i_dev, r_dev, i_intent=None, r_intent=None,
                          expect_failure=False, i_freq=None, r_freq=None):
    i_dev.p2p_listen()
    logger.info("Start GO negotiation " + i_dev.ifname + " -> " + r_dev.ifname)
    r_dev.p2p_go_neg_auth(i_dev.p2p_dev_addr(), None, "pbc",
                          go_intent=r_intent, freq=r_freq)
    r_dev.p2p_listen()
    i_res = i_dev.p2p_go_neg_init(r_dev.p2p_dev_addr(), None, "pbc", timeout=20,
                                  go_intent=i_intent,
                                  expect_failure=expect_failure, freq=i_freq)
    r_res = r_dev.p2p_go_neg_auth_result(expect_failure=expect_failure)
    logger.debug("i_res: " + str(i_res))
    logger.debug("r_res: " + str(r_res))
    r_dev.dump_monitor()
    i_dev.dump_monitor()
    if expect_failure:
        return
    logger.info("Group formed")
    return [i_res, r_res]

def remove_group(dev1, dev2):
    dev1.remove_group()
    try:
        dev2.remove_group()
    except:
        pass

def test_grpform(dev):
    """P2P group formation using PIN and authorized connection (init -> GO)"""
    try:
        dev[0].global_request("SET p2p_group_idle 2")
        [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                               r_dev=dev[1], r_intent=0)
        check_grpform_results(i_res, r_res)
        dev[1].remove_group()
        ev = dev[0].wait_global_event(["P2P-GROUP-REMOVED"], timeout=10)
        if ev is None:
            raise Exception("GO did not remove group on idle timeout")
        if "GO reason=IDLE" not in ev:
            raise Exception("Unexpected group removal event: " + ev)
    finally:
        dev[0].global_request("SET p2p_group_idle 0")

def test_grpform_a(dev):
    """P2P group formation using PIN and authorized connection (init -> GO) (init: group iface)"""
    dev[0].global_request("SET p2p_no_group_iface 0")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0)
    if "p2p-wlan" not in i_res['ifname']:
        raise Exception("Unexpected group interface name")
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])
    if i_res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")

def test_grpform_b(dev):
    """P2P group formation using PIN and authorized connection (init -> GO) (resp: group iface)"""
    dev[1].global_request("SET p2p_no_group_iface 0")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0)
    if "p2p-wlan" not in r_res['ifname']:
        raise Exception("Unexpected group interface name")
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])
    if r_res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")

def test_grpform_c(dev):
    """P2P group formation using PIN and authorized connection (init -> GO) (group iface)"""
    dev[0].global_request("SET p2p_no_group_iface 0")
    dev[1].global_request("SET p2p_no_group_iface 0")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0)
    if "p2p-wlan" not in i_res['ifname']:
        raise Exception("Unexpected group interface name")
    if "p2p-wlan" not in r_res['ifname']:
        raise Exception("Unexpected group interface name")
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])
    if i_res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")
    if r_res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")

def test_grpform2(dev):
    """P2P group formation using PIN and authorized connection (resp -> GO)"""
    go_neg_pin_authorized(i_dev=dev[0], i_intent=0, r_dev=dev[1], r_intent=15)
    remove_group(dev[0], dev[1])

def test_grpform2_c(dev):
    """P2P group formation using PIN and authorized connection (resp -> GO) (group iface)"""
    dev[0].global_request("SET p2p_no_group_iface 0")
    dev[1].global_request("SET p2p_no_group_iface 0")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0, r_dev=dev[1], r_intent=15)
    remove_group(dev[0], dev[1])
    if i_res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")
    if r_res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")

def test_grpform3(dev):
    """P2P group formation using PIN and re-init GO Negotiation"""
    go_neg_pin(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    remove_group(dev[0], dev[1])

def test_grpform3_c(dev):
    """P2P group formation using PIN and re-init GO Negotiation (group iface)"""
    dev[0].global_request("SET p2p_no_group_iface 0")
    dev[1].global_request("SET p2p_no_group_iface 0")
    [i_res, r_res] = go_neg_pin(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    remove_group(dev[0], dev[1])
    if i_res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")
    if r_res['ifname'] in utils.get_ifnames():
        raise Exception("Group interface netdev was not removed")

def test_grpform4(dev):
    """P2P group formation response during p2p_find"""
    addr1 = dev[1].p2p_dev_addr()
    dev[1].p2p_listen()
    dev[0].discover_peer(addr1)
    dev[1].p2p_find(social=True)
    time.sleep(0.4)
    dev[0].global_request("P2P_CONNECT " + addr1 + " 12345670 display")
    ev = dev[1].wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation RX timed out")
    time.sleep(0.5)
    dev[1].p2p_stop_find()
    dev[0].p2p_stop_find()

def test_grpform_pbc(dev):
    """P2P group formation using PBC and re-init GO Negotiation"""
    [i_res, r_res] = go_neg_pbc(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    check_grpform_results(i_res, r_res)
    if i_res['role'] != 'GO' or r_res['role'] != 'client':
        raise Exception("Unexpected device roles")
    remove_group(dev[0], dev[1])

def test_grpform_pd(dev):
    """P2P group formation with PD-before-GO-Neg workaround"""
    [i_res, r_res] = go_neg_pbc(i_dev=dev[0], provdisc=True, r_dev=dev[1], r_listen=True)
    check_grpform_results(i_res, r_res)
    remove_group(dev[0], dev[1])

def test_grpform_ext_listen(dev):
    """P2P group formation with extended listen timing enabled"""
    addr0 = dev[0].p2p_dev_addr()
    try:
        if "FAIL" not in dev[0].global_request("P2P_EXT_LISTEN 100"):
            raise Exception("Invalid P2P_EXT_LISTEN accepted")
        if "OK" not in dev[0].global_request("P2P_EXT_LISTEN 300 1000"):
            raise Exception("Failed to set extended listen timing")
        if "OK" not in dev[1].global_request("P2P_EXT_LISTEN 200 40000"):
            raise Exception("Failed to set extended listen timing")
        [i_res, r_res] = go_neg_pbc(i_dev=dev[0], provdisc=True, r_dev=dev[1],
                                    r_listen=True, i_freq="2417", r_freq="2417",
                                    i_intent=1, r_intent=15)
        check_grpform_results(i_res, r_res)
        peer1 = dev[0].get_peer(dev[1].p2p_dev_addr())
        if peer1['ext_listen_interval'] != "40000":
            raise Exception("Extended listen interval not discovered correctly")
        if peer1['ext_listen_period'] != "200":
            raise Exception("Extended listen period not discovered correctly")
        peer0 = dev[1].get_peer(dev[0].p2p_dev_addr())
        if peer0['ext_listen_interval'] != "1000":
            raise Exception("Extended listen interval not discovered correctly")
        if peer0['ext_listen_period'] != "300":
            raise Exception("Extended listen period not discovered correctly")
        if not dev[2].discover_peer(addr0):
            raise Exception("Could not discover peer during ext listen")
        remove_group(dev[0], dev[1])
    finally:
        if "OK" not in dev[0].global_request("P2P_EXT_LISTEN"):
            raise Exception("Failed to clear extended listen timing")
        if "OK" not in dev[1].global_request("P2P_EXT_LISTEN"):
            raise Exception("Failed to clear extended listen timing")

def test_grpform_ext_listen_oper(dev):
    """P2P extended listen timing operations"""
    try:
        _test_grpform_ext_listen_oper(dev)
    finally:
        dev[0].global_request("P2P_EXT_LISTEN")

def _test_grpform_ext_listen_oper(dev):
    addr0 = dev[0].p2p_dev_addr()
    dev[0].global_request("SET p2p_no_group_iface 0")
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")
    addr1 = wpas.p2p_dev_addr()
    wpas.request("P2P_SET listen_channel 1")
    wpas.global_request("SET p2p_no_group_iface 0")
    wpas.request("P2P_LISTEN")
    if not dev[0].discover_peer(addr1):
        raise Exception("Could not discover peer")
    dev[0].request("P2P_LISTEN")
    if not wpas.discover_peer(addr0):
        raise Exception("Could not discover peer (2)")

    dev[0].global_request("P2P_EXT_LISTEN 300 500")
    dev[0].global_request("P2P_CONNECT " + addr1 + " 12345670 display auth go_intent=0 freq=2417")
    wpas.global_request("P2P_CONNECT " + addr0 + " 12345670 enter go_intent=15 freq=2417")
    ev = dev[0].wait_global_event(["P2P-GO-NEG-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation failed")
    ifaces = wpas.request("INTERFACES").splitlines()
    iface = ifaces[0] if "p2p-wlan" in ifaces[0] else ifaces[1]
    wpas.group_ifname = iface
    if "OK" not in wpas.group_request("STOP_AP"):
        raise Exception("STOP_AP failed")
    wpas.group_request("SET ext_mgmt_frame_handling 1")
    dev[1].p2p_find(social=True)
    time.sleep(1)
    if dev[1].peer_known(addr0):
        raise Exception("Unexpected peer discovery")
    ifaces = dev[0].request("INTERFACES").splitlines()
    iface = ifaces[0] if "p2p-wlan" in ifaces[0] else ifaces[1]
    if "OK" not in dev[0].global_request("P2P_GROUP_REMOVE " + iface):
        raise Exception("Failed to request group removal")
    wpas.remove_group()

    count = 0
    timeout = 15
    found = False
    while count < timeout * 4:
        time.sleep(0.25)
        count = count + 1
        if dev[1].peer_known(addr0):
            found = True
            break
    dev[1].p2p_stop_find()
    if not found:
        raise Exception("Could not discover peer that was supposed to use extended listen")

def test_both_go_intent_15(dev):
    """P2P GO Negotiation with both devices using GO intent 15"""
    go_neg_pin_authorized(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=15, expect_failure=True, i_go_neg_status=9)

def test_both_go_neg_display(dev):
    """P2P GO Negotiation with both devices trying to display PIN"""
    go_neg_pin_authorized(i_dev=dev[0], r_dev=dev[1], expect_failure=True, i_go_neg_status=10, i_method='display', r_method='display')

def test_both_go_neg_enter(dev):
    """P2P GO Negotiation with both devices trying to enter PIN"""
    go_neg_pin_authorized(i_dev=dev[0], r_dev=dev[1], expect_failure=True, i_go_neg_status=10, i_method='enter', r_method='enter')

def test_go_neg_pbc_vs_pin(dev):
    """P2P GO Negotiation with one device using PBC and the other PIN"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1):
        raise Exception("Could not discover peer")
    dev[0].p2p_listen()
    if "OK" not in dev[0].request("P2P_CONNECT " + addr1 + " pbc auth"):
        raise Exception("Failed to authorize GO Neg")
    if not dev[1].discover_peer(addr0):
        raise Exception("Could not discover peer")
    if "OK" not in dev[1].request("P2P_CONNECT " + addr0 + " 12345670 display"):
        raise Exception("Failed to initiate GO Neg")
    ev = dev[1].wait_global_event(["P2P-GO-NEG-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("GO Negotiation failure timed out")
    if "status=10" not in ev:
        raise Exception("Unexpected failure reason: " + ev)

def test_go_neg_pin_vs_pbc(dev):
    """P2P GO Negotiation with one device using PIN and the other PBC"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1):
        raise Exception("Could not discover peer")
    dev[0].p2p_listen()
    if "OK" not in dev[0].request("P2P_CONNECT " + addr1 + " 12345670 display auth"):
        raise Exception("Failed to authorize GO Neg")
    if not dev[1].discover_peer(addr0):
        raise Exception("Could not discover peer")
    if "OK" not in dev[1].request("P2P_CONNECT " + addr0 + " pbc"):
        raise Exception("Failed to initiate GO Neg")
    ev = dev[1].wait_global_event(["P2P-GO-NEG-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("GO Negotiation failure timed out")
    if "status=10" not in ev:
        raise Exception("Unexpected failure reason: " + ev)

def test_grpform_per_sta_psk(dev):
    """P2P group formation with per-STA PSKs"""
    dev[0].global_request("P2P_SET per_sta_psk 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    check_grpform_results(i_res, r_res)

    pin = dev[2].wps_read_pin()
    dev[0].p2p_go_authorize_client(pin)
    c_res = dev[2].p2p_connect_group(dev[0].p2p_dev_addr(), pin, timeout=60)
    check_grpform_results(i_res, c_res)

    if r_res['psk'] == c_res['psk']:
        raise Exception("Same PSK assigned for both clients")

    hwsim_utils.test_connectivity_p2p(dev[1], dev[2])

    dev[0].remove_group()
    dev[1].wait_go_ending_session()
    dev[2].wait_go_ending_session()

def test_grpform_per_sta_psk_wps(dev):
    """P2P group formation with per-STA PSKs with non-P2P WPS STA"""
    dev[0].global_request("P2P_SET per_sta_psk 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15, r_dev=dev[1], r_intent=0)
    check_grpform_results(i_res, r_res)

    dev[0].p2p_go_authorize_client_pbc()
    dev[2].request("WPS_PBC")
    dev[2].wait_connected(timeout=30)

    hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])

    dev[0].remove_group()
    dev[2].request("DISCONNECT")
    dev[1].wait_go_ending_session()

def test_grpform_force_chan_go(dev):
    """P2P group formation forced channel selection by GO"""
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           i_freq=2432,
                                           r_dev=dev[1], r_intent=0,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if i_res['freq'] != "2432":
        raise Exception("Unexpected channel - did not follow GO's forced channel")
    remove_group(dev[0], dev[1])

def test_grpform_force_chan_cli(dev):
    """P2P group formation forced channel selection by client"""
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           i_freq=2417,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if i_res['freq'] != "2417":
        raise Exception("Unexpected channel - did not follow GO's forced channel")
    remove_group(dev[0], dev[1])

def test_grpform_force_chan_conflict(dev):
    """P2P group formation fails due to forced channel mismatch"""
    go_neg_pin_authorized(i_dev=dev[0], i_intent=0, i_freq=2422,
                          r_dev=dev[1], r_intent=15, r_freq=2427,
                          expect_failure=True, i_go_neg_status=7)

def test_grpform_pref_chan_go(dev):
    """P2P group formation preferred channel selection by GO"""
    dev[0].request("SET p2p_pref_chan 81:7")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if i_res['freq'] != "2442":
        raise Exception("Unexpected channel - did not follow GO's p2p_pref_chan")
    remove_group(dev[0], dev[1])

def test_grpform_pref_chan_go_overridden(dev):
    """P2P group formation preferred channel selection by GO overridden by client"""
    dev[1].request("SET p2p_pref_chan 81:7")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           i_freq=2422,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if i_res['freq'] != "2422":
        raise Exception("Unexpected channel - did not follow client's forced channel")
    remove_group(dev[0], dev[1])

def test_grpform_no_go_freq_forcing_chan(dev):
    """P2P group formation with no-GO freq forcing channel"""
    dev[1].request("SET p2p_no_go_freq 100-200,300,4000-6000")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow no-GO freq")
    remove_group(dev[0], dev[1])

def test_grpform_no_go_freq_conflict(dev):
    """P2P group formation fails due to no-GO range forced by client"""
    dev[1].request("SET p2p_no_go_freq 2000-3000")
    go_neg_pin_authorized(i_dev=dev[0], i_intent=0, i_freq=2422,
                          r_dev=dev[1], r_intent=15,
                          expect_failure=True, i_go_neg_status=7)

def test_grpform_no_5ghz_world_roaming(dev):
    """P2P group formation with world roaming regulatory"""
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_no_5ghz_add_cli(dev):
    """P2P group formation with passive scan 5 GHz and p2p_add_cli_chan=1"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=14,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_no_5ghz_add_cli2(dev):
    """P2P group formation with passive scan 5 GHz and p2p_add_cli_chan=1 (reverse)"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=14,
                                           r_dev=dev[1], r_intent=0,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_no_5ghz_add_cli3(dev):
    """P2P group formation with passive scan 5 GHz and p2p_add_cli_chan=1 (intent 15)"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=0,
                                           r_dev=dev[1], r_intent=15,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_no_5ghz_add_cli4(dev):
    """P2P group formation with passive scan 5 GHz and p2p_add_cli_chan=1 (reverse; intent 15)"""
    dev[0].request("SET p2p_add_cli_chan 1")
    dev[1].request("SET p2p_add_cli_chan 1")
    [i_res, r_res] = go_neg_pin_authorized(i_dev=dev[0], i_intent=15,
                                           r_dev=dev[1], r_intent=0,
                                           test_data=False)
    check_grpform_results(i_res, r_res)
    if int(i_res['freq']) > 4000:
        raise Exception("Unexpected channel - did not follow world roaming rules")
    remove_group(dev[0], dev[1])

def test_grpform_incorrect_pin(dev):
    """P2P GO Negotiation with incorrect PIN"""
    dev[1].p2p_listen()
    addr1 = dev[1].p2p_dev_addr()
    if not dev[0].discover_peer(addr1):
        raise Exception("Peer not found")
    res = dev[1].global_request("P2P_CONNECT " + dev[0].p2p_dev_addr() + " pin auth go_intent=0")
    if "FAIL" in res:
        raise Exception("P2P_CONNECT failed to generate PIN")
    logger.info("PIN from P2P_CONNECT: " + res)
    dev[0].global_request("P2P_CONNECT " + addr1 + " 00000000 enter go_intent=15")
    ev = dev[0].wait_global_event(["P2P-GO-NEG-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation did not complete successfully(0)")
    ev = dev[1].wait_global_event(["P2P-GO-NEG-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation did not complete successfully(1)")
    ev = dev[1].wait_global_event(["WPS-FAIL"], timeout=15)
    if ev is None:
        raise Exception("WPS failure not reported(1)")
    if "msg=8 config_error=18" not in ev:
        raise Exception("Unexpected WPS failure(1): " + ev)
    ev = dev[0].wait_global_event(["WPS-FAIL"], timeout=15)
    if ev is None:
        raise Exception("WPS failure not reported")
    if "msg=8 config_error=18" not in ev:
        raise Exception("Unexpected WPS failure: " + ev)
    ev = dev[1].wait_global_event(["P2P-GROUP-FORMATION-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("Group formation failure timed out")
    ev = dev[0].wait_global_event(["P2P-GROUP-FORMATION-FAILURE"], timeout=5)
    if ev is None:
        raise Exception("Group formation failure timed out")

def test_grpform_reject(dev):
    """User rejecting group formation attempt by a P2P peer"""
    addr0 = dev[0].p2p_dev_addr()
    dev[0].p2p_listen()
    dev[1].p2p_go_neg_init(addr0, None, "pbc")
    ev = dev[0].wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=15)
    if ev is None:
        raise Exception("GO Negotiation timed out")
    if "OK" in dev[0].global_request("P2P_REJECT foo"):
        raise Exception("Invalid P2P_REJECT accepted")
    if "FAIL" in dev[0].global_request("P2P_REJECT " + ev.split(' ')[1]):
        raise Exception("P2P_REJECT failed")
    dev[1].request("P2P_STOP_FIND")
    dev[1].p2p_go_neg_init(addr0, None, "pbc")
    ev = dev[1].wait_global_event(["GO-NEG-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("Rejection not reported")
    if "status=11" not in ev:
        raise Exception("Unexpected status code in rejection")

def test_grpform_pd_no_probe_resp(dev):
    """GO Negotiation after PD, but no Probe Response"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[0].p2p_listen()
    if not dev[1].discover_peer(addr0):
        raise Exception("Peer not found")
    dev[1].p2p_stop_find()
    dev[0].p2p_stop_find()
    peer = dev[0].get_peer(addr1)
    if peer['listen_freq'] == '0':
        raise Exception("Peer listen frequency not learned from Probe Request")
    time.sleep(0.3)
    dev[0].request("P2P_FLUSH")
    dev[0].p2p_listen()
    dev[1].global_request("P2P_PROV_DISC " + addr0 + " display")
    ev = dev[0].wait_global_event(["P2P-PROV-DISC-SHOW-PIN"], timeout=5)
    if ev is None:
        raise Exception("PD Request timed out")
    ev = dev[1].wait_global_event(["P2P-PROV-DISC-ENTER-PIN"], timeout=5)
    if ev is None:
        raise Exception("PD Response timed out")
    peer = dev[0].get_peer(addr1)
    if peer['listen_freq'] != '0':
        raise Exception("Peer listen frequency learned unexpectedly from PD Request")

    pin = dev[0].wps_read_pin()
    if "FAIL" in dev[1].global_request("P2P_CONNECT " + addr0 + " " + pin + " enter"):
        raise Exception("P2P_CONNECT on initiator failed")
    ev = dev[0].wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=5)
    if ev is None:
        raise Exception("GO Negotiation start timed out")
    peer = dev[0].get_peer(addr1)
    if peer['listen_freq'] == '0':
        raise Exception("Peer listen frequency not learned from PD followed by GO Neg Req")
    if "FAIL" in dev[0].global_request("P2P_CONNECT " + addr1 + " " + pin + " display"):
        raise Exception("P2P_CONNECT on responder failed")
    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
    if ev is None:
        raise Exception("Group formation timed out")
    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
    if ev is None:
        raise Exception("Group formation timed out")

def test_go_neg_two_peers(dev):
    """P2P GO Negotiation rejected due to already started negotiation with another peer"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    addr2 = dev[2].p2p_dev_addr()
    dev[1].p2p_listen()
    dev[2].p2p_listen()
    if not dev[0].discover_peer(addr1):
        raise Exception("Could not discover peer")
    if not dev[0].discover_peer(addr2):
        raise Exception("Could not discover peer")
    if "OK" not in dev[0].request("P2P_CONNECT " + addr2 + " pbc auth"):
        raise Exception("Failed to authorize GO Neg")
    dev[0].p2p_listen()
    if not dev[2].discover_peer(addr0):
        raise Exception("Could not discover peer")
    if "OK" not in dev[0].request("P2P_CONNECT " + addr1 + " pbc"):
        raise Exception("Failed to initiate GO Neg")
    ev = dev[1].wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=5)
    if ev is None:
        raise Exception("timeout on GO Neg RX event")
    dev[2].request("P2P_CONNECT " + addr0 + " pbc")
    ev = dev[2].wait_global_event(["GO-NEG-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("Rejection not reported")
    if "status=5" not in ev:
        raise Exception("Unexpected status code in rejection: " + ev)

def clear_pbc_overlap(dev, ifname):
    hapd_global = hostapd.HostapdGlobal()
    hapd_global.remove(ifname)
    dev[0].request("P2P_CANCEL")
    dev[1].request("P2P_CANCEL")
    dev[0].p2p_stop_find()
    dev[1].p2p_stop_find()
    dev[0].dump_monitor()
    dev[1].dump_monitor()
    time.sleep(0.1)
    dev[0].flush_scan_cache()
    dev[1].flush_scan_cache()
    time.sleep(0.1)

def test_grpform_pbc_overlap(dev, apdev):
    """P2P group formation during PBC overlap"""
    params = { "ssid": "wps", "eap_server": "1", "wps_state": "1" }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    hapd.request("WPS_PBC")
    time.sleep(0.1)

    # Since P2P Client scan case is now optimzied to use a specific SSID, the
    # WPS AP will not reply to that and the scan after GO Negotiation can quite
    # likely miss the AP due to dwell time being short enoguh to miss the Beacon
    # frame. This has made the test case somewhat pointless, but keep it here
    # for now with an additional scan to confirm that PBC detection works if
    # there is a BSS entry for a overlapping AP.
    for i in range(0, 5):
        dev[0].scan(freq="2412")
        if dev[0].get_bss(apdev[0]['bssid']) is not None:
            break

    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[0].p2p_listen()
    if not dev[1].discover_peer(addr0):
        raise Exception("Could not discover peer")
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1):
        raise Exception("Could not discover peer")
    dev[0].p2p_listen()
    if "OK" not in dev[0].global_request("P2P_CONNECT " + addr1 + " pbc auth go_intent=0"):
        raise Exception("Failed to authorize GO Neg")
    if "OK" not in dev[1].global_request("P2P_CONNECT " + addr0 + " pbc go_intent=15 freq=2412"):
        raise Exception("Failed to initiate GO Neg")
    ev = dev[0].wait_global_event(["WPS-OVERLAP-DETECTED"], timeout=15)
    if ev is None:
        raise Exception("PBC overlap not reported")

    clear_pbc_overlap(dev, apdev[0]['ifname'])

def test_grpform_pbc_overlap_group_iface(dev, apdev):
    """P2P group formation during PBC overlap using group interfaces"""
    # Note: Need to include P2P IE from the AP to get the P2P interface BSS
    # update use this information.
    params = { "ssid": "wps", "eap_server": "1", "wps_state": "1",
               "beacon_int": "15", 'manage_p2p': '1' }
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)
    hapd.request("WPS_PBC")

    dev[0].request("SET p2p_no_group_iface 0")
    dev[1].request("SET p2p_no_group_iface 0")

    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[0].p2p_listen()
    if not dev[1].discover_peer(addr0):
        raise Exception("Could not discover peer")
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1):
        raise Exception("Could not discover peer")
    dev[0].p2p_stop_find()
    dev[0].scan(freq="2412")
    dev[0].p2p_listen()
    if "OK" not in dev[0].global_request("P2P_CONNECT " + addr1 + " pbc auth go_intent=0"):
        raise Exception("Failed to authorize GO Neg")
    if "OK" not in dev[1].global_request("P2P_CONNECT " + addr0 + " pbc go_intent=15 freq=2412"):
        raise Exception("Failed to initiate GO Neg")
    ev = dev[0].wait_global_event(["WPS-OVERLAP-DETECTED",
                                   "P2P-GROUP-FORMATION-SUCCESS"], timeout=15)
    if ev is None or "WPS-OVERLAP-DETECTED" not in ev:
        # Do not report this as failure since the P2P group formation case
        # using a separate group interface has limited chances of "seeing" the
        # overlapping AP due to a per-SSID scan and no prior scan operations on
        # the group interface.
        logger.info("PBC overlap not reported")

    clear_pbc_overlap(dev, apdev[0]['ifname'])

def test_grpform_goneg_fail_with_group_iface(dev):
    """P2P group formation fails while using group interface"""
    dev[0].request("SET p2p_no_group_iface 0")
    dev[1].p2p_listen()
    peer = dev[1].p2p_dev_addr()
    if not dev[0].discover_peer(peer):
        raise Exception("Peer " + peer + " not found")
    if "OK" not in dev[1].request("P2P_REJECT " + dev[0].p2p_dev_addr()):
        raise Exception("P2P_REJECT failed")
    if "OK" not in dev[0].request("P2P_CONNECT " + peer + " pbc"):
        raise Exception("P2P_CONNECT failed")
    ev = dev[0].wait_global_event(["P2P-GO-NEG-FAILURE"], timeout=10)
    if ev is None:
        raise Exception("GO Negotiation failure timed out")

def test_grpform_cred_ready_timeout(dev, apdev, params):
    """P2P GO Negotiation wait for credentials to become ready [long]"""
    if not params['long']:
        raise HwsimSkip("Skip test case with long duration due to --long not specified")

    dev[1].p2p_listen()
    addr1 = dev[1].p2p_dev_addr()
    if not dev[0].discover_peer(addr1):
        raise Exception("Peer " + addr1 + " not found")
    if not dev[2].discover_peer(addr1):
        raise Exception("Peer " + addr1 + " not found(2)")

    start = os.times()[4]

    cmd = "P2P_CONNECT " + addr1 + " 12345670 display"
    if "OK" not in dev[0].global_request(cmd):
        raise Exception("Failed to initiate GO Neg")

    if "OK" not in dev[2].global_request(cmd):
        raise Exception("Failed to initiate GO Neg(2)")

    # First, check with p2p_find
    ev = dev[2].wait_global_event(["P2P-GO-NEG-FAILURE"], timeout=30)
    if ev is not None:
        raise Exception("Too early GO Negotiation timeout reported(2)")
    dev[2].dump_monitor()
    logger.info("Starting p2p_find to change state")
    dev[2].p2p_find()
    ev = dev[2].wait_global_event(["P2P-GO-NEG-FAILURE"], timeout=100)
    if ev is None:
        raise Exception("GO Negotiation failure timed out(2)")
    dev[2].dump_monitor()
    end = os.times()[4]
    logger.info("GO Negotiation wait time: {} seconds(2)".format(end - start))
    if end - start < 120:
        raise Exception("Too short GO Negotiation wait time(2): {}".format(end - start))

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5")

    wpas.p2p_listen()
    ev = dev[2].wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
    if ev is None:
        raise Exception("Did not discover new device after GO Negotiation failure")
    if wpas.p2p_dev_addr() not in ev:
        raise Exception("Unexpected device found: " + ev)
    dev[2].p2p_stop_find()
    wpas.p2p_stop_find()

    # Finally, verify without p2p_find
    ev = dev[0].wait_global_event(["P2P-GO-NEG-FAILURE"], timeout=120)
    if ev is None:
        raise Exception("GO Negotiation failure timed out")
    end = os.times()[4]
    logger.info("GO Negotiation wait time: {} seconds".format(end - start))
    if end - start < 120:
        raise Exception("Too short GO Negotiation wait time: {}".format(end - start))

def test_grpform_no_wsc_done(dev):
    """P2P group formation with WSC-Done not sent"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()

    for i in range(0, 2):
        dev[0].request("SET ext_eapol_frame_io 1")
        dev[1].request("SET ext_eapol_frame_io 1")
        dev[0].p2p_listen()
        dev[1].p2p_go_neg_auth(addr0, "12345670", "display", 0)
        dev[1].p2p_listen()
        dev[0].p2p_go_neg_init(addr1, "12345670", "enter", timeout=20,
                               go_intent=15, wait_group=False)

        mode = None
        while True:
            ev = dev[0].wait_event(["EAPOL-TX"], timeout=15)
            if ev is None:
                raise Exception("Timeout on EAPOL-TX from GO")
            if not mode:
                mode = dev[0].get_status_field("mode")
            res = dev[1].request("EAPOL_RX " + addr0 + " " + ev.split(' ')[2])
            if "OK" not in res:
                raise Exception("EAPOL_RX failed")
            ev = dev[1].wait_event(["EAPOL-TX"], timeout=15)
            if ev is None:
                raise Exception("Timeout on EAPOL-TX from P2P Client")
            msg = ev.split(' ')[2]
            if msg[46:56] == "102200010f":
                logger.info("Drop WSC_Done")
                dev[0].request("SET ext_eapol_frame_io 0")
                dev[1].request("SET ext_eapol_frame_io 0")
                # Fake EAP-Failure to complete session on the client
                id = msg[10:12]
                dev[1].request("EAPOL_RX " + addr0 + " 0300000404" + id + "0004")
                break
            res = dev[0].request("EAPOL_RX " + addr1 + " " + msg)
            if "OK" not in res:
                raise Exception("EAPOL_RX failed")

        ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
        if ev is None:
            raise Exception("Group formation timed out on GO")
        ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
        if ev is None:
            raise Exception("Group formation timed out on P2P Client")
        dev[0].remove_group()
        dev[1].wait_go_ending_session()

        if mode != "P2P GO - group formation":
            raise Exception("Unexpected mode on GO during group formation: " + mode)

def test_grpform_wait_peer(dev):
    """P2P group formation wait for peer to become ready"""
    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[1].p2p_listen()
    if not dev[0].discover_peer(addr1):
        raise Exception("Peer " + addr1 + " not found")
    dev[0].request("SET extra_roc_dur 500")
    if "OK" not in dev[0].request("P2P_CONNECT " + addr1 + " 12345670 display go_intent=15"):
        raise Exception("Failed to initiate GO Neg")
    time.sleep(3)
    dev[1].request("P2P_CONNECT " + addr0 + " 12345670 enter go_intent=0")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[0].group_form_result(ev)

    dev[0].request("SET extra_roc_dur 0")
    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=15)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[0].remove_group()

def test_invalid_p2p_connect_command(dev):
    """P2P_CONNECT error cases"""
    id = dev[0].add_network()
    for cmd in [ "foo",
                 "00:11:22:33:44:55",
                 "00:11:22:33:44:55 pbc persistent=123",
                 "00:11:22:33:44:55 pbc persistent=%d" % id,
                 "00:11:22:33:44:55 pbc go_intent=-1",
                 "00:11:22:33:44:55 pbc go_intent=16",
                 "00:11:22:33:44:55 pin",
                 "00:11:22:33:44:55 pbc freq=0" ]:
        if "FAIL" not in dev[0].request("P2P_CONNECT " + cmd):
            raise Exception("Invalid P2P_CONNECT command accepted: " + cmd)

    if "FAIL-INVALID-PIN" not in dev[0].request("P2P_CONNECT 00:11:22:33:44:55 1234567"):
        raise Exception("Invalid PIN was not rejected")
    if "FAIL-INVALID-PIN" not in dev[0].request("P2P_CONNECT 00:11:22:33:44:55 12345678a"):
        raise Exception("Invalid PIN was not rejected")

    if "FAIL-CHANNEL-UNSUPPORTED" not in dev[0].request("P2P_CONNECT 00:11:22:33:44:55 pin freq=3000"):
        raise Exception("Unsupported channel not reported")

def test_p2p_unauthorize(dev):
    """P2P_UNAUTHORIZE to unauthorize a peer"""
    if "FAIL" not in dev[0].request("P2P_UNAUTHORIZE foo"):
        raise Exception("Invalid P2P_UNAUTHORIZE accepted")
    if "FAIL" not in dev[0].request("P2P_UNAUTHORIZE 00:11:22:33:44:55"):
        raise Exception("P2P_UNAUTHORIZE for unknown peer accepted")

    addr0 = dev[0].p2p_dev_addr()
    addr1 = dev[1].p2p_dev_addr()
    dev[1].p2p_listen()
    pin = dev[0].wps_read_pin()
    dev[0].p2p_go_neg_auth(addr1, pin, "display")
    dev[0].p2p_listen()
    if "OK" not in dev[0].request("P2P_UNAUTHORIZE " + addr1):
        raise Exception("P2P_UNAUTHORIZE failed")
    dev[1].p2p_go_neg_init(addr0, pin, "keypad", timeout=0)
    ev = dev[0].wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=10)
    if ev is None:
        raise Exception("No GO Negotiation Request RX reported")

def test_grpform_pbc_multiple(dev):
    """P2P group formation using PBC multiple times in a row"""
    try:
        dev[1].request("SET passive_scan 1")
        for i in range(5):
            [i_res, r_res] = go_neg_pbc_authorized(i_dev=dev[0], i_intent=15,
                                                   r_dev=dev[1], r_intent=0)
            remove_group(dev[0], dev[1])
    finally:
        dev[1].request("SET passive_scan 0")
        dev[1].flush_scan_cache()

def test_grpform_not_ready(dev):
    """Not ready for GO Negotiation (listen)"""
    addr0 = dev[0].p2p_dev_addr()
    addr2 = dev[2].p2p_dev_addr()
    dev[0].p2p_listen()
    if not dev[1].discover_peer(addr0):
        raise Exception("Could not discover peer")
    dev[1].global_request("P2P_CONNECT " + addr0 + " pbc")
    ev = dev[0].wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=5)
    if ev is None:
        raise Exception("No P2P-GO-NEG-REQUEST event")
    dev[0].dump_monitor()
    time.sleep(5)
    if not dev[2].discover_peer(addr0):
        raise Exception("Could not discover peer(2)")
    for i in range(3):
        dev[i].p2p_stop_find()

def test_grpform_not_ready2(dev):
    """Not ready for GO Negotiation (search)"""
    addr0 = dev[0].p2p_dev_addr()
    addr2 = dev[2].p2p_dev_addr()
    dev[0].p2p_find(social=True)
    if not dev[1].discover_peer(addr0):
        raise Exception("Could not discover peer")
    dev[1].global_request("P2P_CONNECT " + addr0 + " pbc")
    ev = dev[0].wait_global_event(["P2P-GO-NEG-REQUEST"], timeout=5)
    if ev is None:
        raise Exception("No P2P-GO-NEG-REQUEST event")
    dev[0].dump_monitor()
    time.sleep(1)
    dev[2].p2p_listen()
    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
    if ev is None:
        raise Exception("Peer not discovered after GO Neg Resp(status=1) TX")
    if addr2 not in ev:
        raise Exception("Unexpected peer discovered: " + ev)
    for i in range(3):
        dev[i].p2p_stop_find()
