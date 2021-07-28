# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

# Copyright (C) 2017 CESNET, a.l.e.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import logging
from pysnmp.hlapi.asyncore import *
from django.conf import settings
from datetime import datetime, timedelta
import json
import os
import time

from flowspec.models import Route
from flowspec.junos import create_junos_name

logger = logging.getLogger(__name__)
identoffset = len(settings.SNMP_CNTPACKETS) + 1

# Wait for responses or errors, submit GETNEXT requests for further OIDs
# noinspection PyUnusedLocal,PyUnusedLocal
def snmpCallback(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBindTable, cbCtx):
    (authData, transportTarget, results) = cbCtx

    # debug - which router replies:
    #print('%s via %s' % (authData, transportTarget))

    # CNTPACKETS and CNTBYTES are of the same length
    if errorIndication:
        logger.error('Bad errorIndication.')
        return 0
    elif errorStatus:
        logger.error('Bad errorStatus.')
        return 0
    for varBindRow in varBindTable:
        for name, val in varBindRow:
            name = str(name)
            if name.startswith(settings.SNMP_CNTPACKETS):
                counter = "packets"
            elif name.startswith(settings.SNMP_CNTBYTES):
                counter = "bytes"
            else:
                logger.info('Finished {}.'.format(transportTarget))
                return 0

            ident = name[identoffset:]
            ordvals = [int(i) for i in ident.split(".")]
            # the first byte is length of table name string
            len1 = ordvals[0] + 1
            tablename = "".join([chr(i) for i in ordvals[1:len1]])
            if tablename in settings.SNMP_RULESFILTER:
                # if the current route belongs to specified table from SNMP_RULESFILTER list,
                # take the route identifier
                len2 = ordvals[len1] + 1
                routename = "".join([chr(i) for i in ordvals[len1 + 1:len1 + len2]])

                # add value into dict
                if routename in results:
                    if counter in results[routename]:
                        results[routename][counter] = results[routename][counter] + int(val)
                    else:
                        results[routename][counter] = int(val)
                else:
                    results[routename] = {counter: int(val)}
                logger.debug("%s %s %s %s = %s" %(transportTarget, counter, tablename, routename, int(val)))

    return 1  # continue table retrieval


def get_snmp_stats():
    """Return dict() of the sum of counters (bytes, packets) from all selected routes, where
    route identifier is the key in dict.  The sum is counted over all routers.

    Example output with one rule: {'77.72.72.1,0/0,proto=1': {'bytes': 13892216, 'packets': 165387}}

    This function uses SNMP_IP list, SNMP_COMMUNITY, SNMP_CNTPACKETS and
    SNMP_RULESFILTER list, all defined in settings."""

    if not isinstance(settings.SNMP_IP, list):
        settings.SNMP_IP = [settings.SNMP_IP]

    results = {}
    targets = []
    # prepare cmdlist
    for ip in settings.SNMP_IP:
        # get values of counters using SNMP
        if isinstance(ip, dict):
            if "port" in ip:
                port = ip["port"]
            else:
                port = 161

            if "community" in ip:
                community = ip["community"]
            else:
                community = settings.SNMP_COMMUNITY
            ip = ip["ip"]
        elif isinstance(ip, str):
            port = 161
            community = settings.SNMP_COMMUNITY
        else:
            raise Exception("Bad configuration of SNMP, SNMP_IP should be a list of dict or a list of str.")

        targets.append((CommunityData(community), UdpTransportTarget((ip, port), timeout=15, retries=1),
                        (ObjectType(ObjectIdentity(settings.SNMP_CNTPACKETS)),
                         #ObjectType(ObjectIdentity(settings.SNMP_CNTBYTES))
                         )))

    snmpEngine = SnmpEngine()

    # Submit initial GETNEXT requests and wait for responses
    for authData, transportTarget, varBinds in targets:
        bulkCmd(snmpEngine, authData, transportTarget, ContextData(), 0, 50,
                *varBinds, **dict(cbFun=snmpCallback, cbCtx=(authData, transportTarget.transportAddr, results)))

    snmpEngine.transportDispatcher.runDispatcher()

    return results

def lock_history_file(wait=1):
    first=1
    success=0
    while first or wait:
      first=0
      try:
          os.mkdir(settings.SNMP_TEMP_FILE+".lock") # TODO use regular file than dir
          logger.info("lock_history_file(): creating lock dir succeeded")
          success=1
          return success
      except OSError as e:
          logger.error("lock_history_file(): creating lock dir failed: OSError: "+str(e))
          success=0
      except Exception as e:
          logger.error("lock_history_file(): lock already exists")
          logger.error("lock_history_file(): creating lock dir failed: "+str(e))
          success=0
      if not success and wait:
        time.sleep(1)
    return success

def unlock_history_file():
    try:
      os.rmdir(settings.SNMP_TEMP_FILE+".lock") # TO DO use regular file than dir
      logger.info("unlock_history_file(): succeeded")
      return 1
    except Exception as e:
      logger.info("unlock_history_file(): failed "+str(e))
      return 0

def load_history():
    history = {}
    try:
        with open(settings.SNMP_TEMP_FILE, "r") as f:
            history = json.load(f)
    except:
        logger.info("There is no file with SNMP historical data.")
        pass
    return history

def save_history(history, nowstr):
    # store updated history
    tf = settings.SNMP_TEMP_FILE + "." + nowstr
    with open(tf, "w") as f:
      json.dump(history, f)
    os.rename(tf, settings.SNMP_TEMP_FILE)

def helper_stats_store_parse_ts(ts_string):
  try:
    ts = datetime.strptime(ts_string, '%Y-%m-%dT%H:%M:%S.%f')
  except Exception as e:
    logger.info("helper_stats_store_parse_ts(): ts_string="+str(ts_string)+": got exception "+str(e))
    ts = None
  return ts

def helper_rule_ts_parse(ts_string):
  try:
    ts = datetime.strptime(ts_string, '%Y-%m-%d %H:%M:%S+00:00') # TODO TZ offset assumed to be 00:00
  except ValueError as e:
    #logger.info("helper_rule_ts_parse(): trying with milli seconds fmt")
    try:
      ts = datetime.strptime(ts_string, '%Y-%m-%d %H:%M:%S.%f+00:00') # TODO TZ offset assumed to be 00:00
    except Exception as e:
      logger.info("helper_rule_ts_parse(): ts_string="+str(ts_string)+": got exception "+str(type(e))+": "+str(e))
      ts = None
  except Exception as e:
    logger.info("helper_rule_ts_parse(): ts_string="+str(ts_string)+": got exception "+str(type(e))+": "+str(e))
    ts = None

  #logger.info("helper_rule_ts_parse(): => ts="+str(ts))
  return ts

def poll_snmp_statistics():
    logger.info("poll_snmp_statistics(): Polling SNMP statistics.")

    # first, determine current ts, before calling get_snmp_stats
    now = datetime.now()
    nowstr = now.isoformat()

    # get new data
    try:
      logger.info("poll_snmp_statistics(): snmpstats: nowstr="+str(nowstr))
      newdata = get_snmp_stats()
    except Exception as e:
      logger.info("poll_snmp_statistics(): get_snmp_stats failed: "+str(e))
      return False

    # lock history file access
    success = lock_history_file(1)
    if not success: 
      logger.error("poll_snmp_statistics(): locking history file failed, aborting");
      return False

    # load history
    history = load_history()

    zero_measurement = { "bytes" : 0, "packets" : 0 }
    null_measurement = 0 
    null_measurement_missing = 1

    try:
      last_poll_no_time = history['_last_poll_no_time']
    except Exception as e:
      logger.info("poll_snmp_statistics(): got exception while trying to access history[_last_poll_time]: "+str(e))
      last_poll_no_time=None
    logger.info("poll_snmp_statistics(): snmpstats: last_poll_no_time="+str(last_poll_no_time))
    history['_last_poll_no_time']=nowstr

    try:
      history_per_rule = history['_per_rule']
    except Exception as e:
      history_per_rule = {}
     
    # do actual update 
    try:
        logger.info("poll_snmp_statistics(): before store: snmpstats: nowstr="+str(nowstr)+", last_poll_no_time="+str(last_poll_no_time))
        #newdata = get_snmp_stats()

        # proper update history
        samplecount = settings.SNMP_MAX_SAMPLECOUNT
        for rule in newdata:
            counter = {"ts": nowstr, "value": newdata[rule]}
            if rule in history:
                history[rule].insert(0, counter)
                history[rule] = history[rule][:samplecount]
            else:
                history[rule] = [counter]

        # check for old rules and remove them
        toremove = []
        for rule in history:
          try:
            #if rule!='_last_poll_no_time' and rule!="_per_rule":
            if rule[:1]!='_':
              #ts = datetime.strptime(history[rule][0]["ts"], '%Y-%m-%dT%H:%M:%S.%f')
              ts = helper_stats_store_parse_ts(history[rule][0]["ts"])
              if ts!=None and (now - ts).total_seconds() >= settings.SNMP_REMOVE_RULES_AFTER:
                  toremove.append(rule)
          except Exception as e:
            logger.info("poll_snmp_statistics(): old rules remove loop: rule="+str(rule)+" got exception "+str(e))
        for rule in toremove:
            history.pop(rule, None)

        if settings.STATISTICS_PER_MATCHACTION_ADD_FINAL_ZERO == True:
          # for now workaround for low-level rules (by match params, not FoD rule id) no longer have data, typically because of haveing been deactivated
          for rule in history:
            #if rule!='_last_poll_no_time' and rule!="_per_rule":
            if rule[:1]!='_':
              ts = history[rule][0]["ts"]
              if ts!=nowstr and ts==last_poll_no_time:
                counter = {"ts": nowstr, "value": null_measurement }
                history[rule].insert(0, counter)
                history[rule] = history[rule][:samplecount]
    
        if settings.STATISTICS_PER_RULE == True:
          queryset = Route.objects.all()
          for ruleobj in queryset:
            rule_id = str(ruleobj.id)
            rule_status = str(ruleobj.status)
            #rule_last_updated = str(ruleobj.last_updated) # e.g. 2018-06-21 08:03:21+00:00
            #rule_last_updated = datetime.strptime(str(ruleobj.last_updated), '%Y-%m-%d %H:%M:%S+00:00') # TODO TZ offset assumed to be 00:00
            rule_last_updated = helper_rule_ts_parse(str(ruleobj.last_updated))
            counter_null = {"ts": rule_last_updated.isoformat(), "value": null_measurement }
            counter_zero = {"ts": rule_last_updated.isoformat(), "value": zero_measurement }

            #logger.info("snmpstats: STATISTICS_PER_RULE ruleobj="+str(ruleobj))
            #logger.info("snmpstats: STATISTICS_PER_RULE ruleobj.type="+str(type(ruleobj)))
            #logger.info("snmpstats: STATISTICS_PER_RULE ruleobj.id="+str(rule_id))
            #logger.info("snmpstats: STATISTICS_PER_RULE ruleobj.status="+rule_status)
            flowspec_params_str=create_junos_name(ruleobj)
            logger.info("snmpstats: STATISTICS_PER_RULE flowspec_params_str="+str(flowspec_params_str))

            if rule_status=="ACTIVE":
              try:
                counter = {"ts": nowstr, "value": newdata[flowspec_params_str]}
                counter_is_null = False
              except Exception as e:
                logger.info("poll_snmp_statistics(): 1 STATISTICS_PER_RULE: exception: rule_id="+str(rule_id)+" newdata for flowspec_params_str='"+str(flowspec_params_str)+"' missing : "+str(e))
                counter = {"ts": nowstr, "value": null_measurement_missing }
                counter_is_null = True
            else:
              counter = {"ts": nowstr, "value": null_measurement }
              counter_is_null = True

            try:
                if not rule_id in history_per_rule:
                  if rule_status!="ACTIVE":
                    logger.info("poll_snmp_statistics(): STATISTICS_PER_RULE: rule_id="+str(rule_id)+" case notexisting inactive")
                    #history_per_rule[rule_id] = [counter]
                  else:
                    logger.info("poll_snmp_statistics(): STATISTICS_PER_RULE: rule_id="+str(rule_id)+" case notexisting active")
                    if counter_is_null:
                      history_per_rule[rule_id] = [counter_zero]
                    else:
                      history_per_rule[rule_id] = [counter, counter_zero]
                else:
                  rec = history_per_rule[rule_id]
                  if rule_status!="ACTIVE":
                    logger.info("poll_snmp_statistics(): STATISTICS_PER_RULE: rule_id="+str(rule_id)+" case existing inactive")
                    rec.insert(0, counter)
                  else:
                    last_value = rec[0]
                    last_is_null = last_value==None or last_value['value'] == null_measurement
                    if last_value==None:
                      rule_newer_than_last = true
                    else:
                      last_ts = helper_stats_store_parse_ts(last_value['ts'])
                      rule_newer_than_last = last_ts==None or rule_last_updated > last_ts
                    logger.info("poll_snmp_statistics(): STATISTICS_PER_RULE: rule_id="+str(rule_id)+" rule_last_updated="+str(rule_last_updated)+", last_value="+str(last_value))
                    if last_is_null and rule_newer_than_last:
                      logger.info("poll_snmp_statistics(): STATISTICS_PER_RULE: rule_id="+str(rule_id)+" case existing active 11")
                      if counter_is_null:
                        rec.insert(0, counter_zero)
                      else:
                        rec.insert(0, counter_zero)
                        rec.insert(0, counter)
                    elif last_is_null and not rule_newer_than_last:
                      logger.info("poll_snmp_statistics(): STATISTICS_PER_RULE: rule_id="+str(rule_id)+" case existing active 10")
                      rec.insert(0, counter_zero)
                      rec.insert(0, counter)
                    elif not last_is_null and rule_newer_than_last:
                      logger.info("poll_snmp_statistics(): STATISTICS_PER_RULE: rule_id="+str(rule_id)+" case existing active 01")
                      if counter_is_null:
                        rec.insert(0, counter_null)
                        rec.insert(0, counter_zero)
                      else:
                        rec.insert(0, counter_null)
                        rec.insert(0, counter_zero)
                        rec.insert(0, counter)
                    elif not last_is_null and not rule_newer_than_last:
                        logger.info("poll_snmp_statistics(): STATISTICS_PER_RULE: rule_id="+str(rule_id)+" case existing active 00")
                        rec.insert(0, counter)

                  history_per_rule[rule_id] = rec[:samplecount]
            except Exception as e:
                logger.info("snmpstats: 2 STATISTICS_PER_RULE: exception: "+str(e))

          history['_per_rule'] = history_per_rule

        # store updated history
        save_history(history, nowstr)
        logger.info("poll_snmp_statistics(): Polling finished.")

    except Exception as e:
        #logger.error(e)
        logger.error("poll_snmp_statistics(): Polling failed. exception: "+str(e))
        logger.error("poll_snmp_statistics(): ", exc_info=True)        
        
    unlock_history_file()
    logger.info("poll_snmp_statistics(): Polling end: last_poll_no_time="+str(last_poll_no_time))

def add_initial_zero_value(rule_id, zero_or_null=True):
    logger.info("add_initial_zero_value(): rule_id="+str(rule_id))

    # get new data
    now = datetime.now()
    nowstr = now.isoformat()

    # lock history file access
    success = lock_history_file(1)
    if not success: 
      logger.error("add_initial_zero_value(): locking history file failed, aborting")
      return False

    # load history
    history = load_history()

    try:
      history_per_rule = history['_per_rule']
    except Exception as e:
      history_per_rule = {}


    if zero_or_null:
      zero_measurement = { "bytes" : 0, "packets" : 0 }
    else:
      zero_measurement = 0
    
    counter = {"ts": nowstr, "value": zero_measurement }
        
    samplecount = settings.SNMP_MAX_SAMPLECOUNT

    try:
        if rule_id in history_per_rule:
              rec = history_per_rule[rule_id]
              last_rec = rec[0]
              if last_rec==None or (zero_or_null and last_rec['value']==0) or ((not zero_or_null) and last_rec['value']!=0):
                rec.insert(0, counter)
                history_per_rule[rule_id] = rec[:samplecount]
        else:
              if zero_or_null:
                history_per_rule[rule_id] = [counter]

        history['_per_rule'] = history_per_rule

        # store updated history
        save_history(history, nowstr)

    except Exception as e:
        logger.info("add_initial_zero_value(): failure: exception: "+str(e))

    unlock_history_file()

