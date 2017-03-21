extern crate snmp;
extern crate zmq;
#[macro_use]
extern crate serde_json;

use std::time::Duration;
use snmp::{SyncSession, ObjectIdentifier};
use std::vec::Vec;

fn walk_oid(addr: &str, community: &[u8], start_oid: &[u32]) {
    let snmp_timeout = Duration::from_secs(2);
    let snmp_bulksize = 10;
    let start_oid_slice = start_oid;
    let start_oid_slice_len = start_oid_slice.len();
    let mut sess = SyncSession::new(addr, community, Some(snmp_timeout), 0).unwrap();
    let mut current_oid: Vec<u32> = start_oid.iter().map(|v| *v as u32).collect();
    let mut in_bounds = true;
    while in_bounds {
        let mut oid: Option<ObjectIdentifier> = None;

        {
            let current_oid_slice = current_oid.as_slice();
            let response = sess.getbulk(&[&current_oid_slice], 0, snmp_bulksize).unwrap();
            for (name, val) in response.varbinds {
                let tmp_oid_slice: &mut [u32; 128] = &mut [0; 128];
                println!("{} => {:?}", name, val);

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
}

fn main() {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::REP).unwrap();
    if socket.bind("ipc:///tmp/kagami.ipc").is_err() {
        println!("failed to bind zmq socket");
        return;
    }
    loop {
        let msg = socket.recv_msg(0).unwrap();
        let result = msg.as_str().unwrap();
        let cmd: serde_json::Value = serde_json::from_str(result).unwrap();
        if cmd["action"] == "walk" {
            if let Some(ref oid) = cmd["oid"].as_str() {
                let mut oidvec: Vec<u32> = Vec::new();
                for snum in oid.split(".") {
                    let res: Result<u32, std::num::ParseIntError> = snum.parse();
                    if res.is_err() {
                        let resp = json!({
                            "status": "failure"
                        });
                        while socket.send_str(&resp.to_string(), 0).is_err() {}
                        continue;
                    }
                    let num = res.unwrap();
                    oidvec.push(num);
                }
                let oid_slice = oidvec.as_slice();
                let agent_addr = "172.24.2.1:161";
                let community = b"m4kai";

                walk_oid(agent_addr, community, oid_slice);

                //let splitvec : Vec<&str> = oid.split(".").collect();
                //println!("{:?}", splitvec);
                //if cmd["oid"].as_str()
                //let ss : String = cmd["oid"].as_str().unwrap().to_string();
                let resp_values: Vec<serde_json::Value> = Vec::new();
                let resp = json!({
                    "status": "ok",
                    "data": resp_values
                });
                while socket.send_str(&resp.to_string(), 0).is_err() {}
            } else {
                let resp = json!({
                    "status": "failure"
                });
                while socket.send_str(&resp.to_string(), 0).is_err() {}
            }
        } else {
            let resp = json!({
                "status": "failure"
            });
            while socket.send_str(&resp.to_string(), 0).is_err() {}
        }
        //println!("jee {}", cmd);
    }

}
