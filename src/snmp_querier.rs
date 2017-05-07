extern crate snmp;
extern crate serde_json;

use std::time::Duration;
use self::snmp::{SyncSession, ObjectIdentifier};
use std::vec::Vec;
use std::str;

pub fn walk_oid(addr: &str, community: &[u8], start_oid: &[u32]) -> Result<Vec<serde_json::Value>,String> {
    let mut ret: Vec<serde_json::Value> = Vec::new();

    let snmp_timeout = Duration::from_secs(1);
    let snmp_bulksize = 20;
    let start_oid_slice = start_oid;
    let start_oid_slice_len = start_oid_slice.len();
    let mut sess = match SyncSession::new(addr, community, Some(snmp_timeout), 0) {
        Ok(sess) => sess,
        Err(err) => return Err(err.to_string()),
    };
    let mut current_oid: Vec<u32> = start_oid.iter().map(|v| *v as u32).collect();
    let mut in_bounds = true;
    while in_bounds {
        let mut oid: Option<ObjectIdentifier> = None;

        {
            let current_oid_slice = current_oid.as_slice();
            let response = match sess.getbulk(&[&current_oid_slice], 0, snmp_bulksize) {
                Ok(response) => response,
                Err(err) => {
                    let error = format!("{:?}", err);
                    return Err(error);
                }
            };
            for (name, val) in response.varbinds {
                let tmp_oid_slice: &mut [u32; 128] = &mut [0; 128];

                if name.read_name(tmp_oid_slice).is_err() {
                    continue;
                }

                let mut cmplen = tmp_oid_slice.len();
                if start_oid_slice_len < cmplen {
                    cmplen = start_oid_slice_len;
                }

                for i in 0..cmplen {
                    if start_oid_slice[i] != tmp_oid_slice[i] {
                        in_bounds = false;
                        break;
                    }
                }

                if !in_bounds {
                    //println!("OOB {} => {:?}", name, val);
                    break;
                } else {
                    let oid_string = format!("{}", name);
                    match val {
                        snmp::Value::Counter32(v) => {
                            ret.push(json!({
                                "oid": oid_string,
                                "value": v as u32
                            }));
                        }
                        snmp::Value::Counter64(v) => {
                            ret.push(json!({
                                "oid": oid_string,
                                "value": v as u64
                            }));
                        }
                        snmp::Value::Unsigned32(v) => {
                            ret.push(json!({
                                "oid": oid_string,
                                "value": v as u32
                            }));
                        }
                        snmp::Value::Timeticks(v) => {
                            ret.push(json!({
                                "oid": oid_string,
                                "value": v as u32
                            }));
                        }
                        snmp::Value::Integer(v) => {
                            ret.push(json!({
                                "oid": oid_string,
                                "value": v as i64
                            }));
                        }
                        snmp::Value::OctetString(v) => {
                            let item = str::from_utf8(v);
                            match item {
                                Ok(s) => {
                                    ret.push(json!({
                                        "oid": oid_string,
                                        "value": s
                                    }));
                                }
                                Err(_) => {
                                    ret.push(json!({
                                        "oid": oid_string,
                                        "value": serde_json::Value::Null
                                    }));
                                }
                            };

                        }
                        snmp::Value::ObjectIdentifier(_) => {}
                        _ => {
                            println!("unhandled: {:?}", val);
                        }
                    }
                }
                oid = Some(name);
            }
        }

        if let Some(ref ref_oid) = oid {
            let mut cur_oid_raw: &mut [u32; 128] = &mut [0; 128];

            if (*ref_oid).read_name(cur_oid_raw).is_err() {
                break;
            }

            current_oid = cur_oid_raw.iter().map(|v| *v as u32).collect();
        } else {
            break;
        }
    }

    return Ok(ret);
}
