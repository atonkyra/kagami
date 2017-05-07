extern crate zmq;
#[macro_use]
extern crate serde_json;

use std::vec::Vec;
mod snmp_querier;


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
        let resp;
        if cmd["action"] == "walk" {
            if let Some(ref oid) = cmd["oid"].as_str() {
                let mut oidvec: Vec<u32> = Vec::new();
                let mut oid_good = true;
                for snum in oid.split(".") {
                    let res: Result<u32, std::num::ParseIntError> = snum.parse();
                    if res.is_err() {
                        oid_good = false;
                        break;
                    }
                    let num = res.unwrap();
                    oidvec.push(num);
                }
                if !oid_good {
                    resp = json!({
                        "status": "error",
                        "error": "oid parse error"
                    });
                } else {
                    let oid_slice = oidvec.as_slice();
                    if let Some(ref agent_addr) = cmd["address"].as_str() {
                        if let Some(ref community) = cmd["community"].as_str() {
                            let community_bytes = community.as_bytes();
                            match snmp_querier::walk_oid(agent_addr, community_bytes, oid_slice) {
                                Ok(v) => {
                                    resp = json!({
                                        "status": "ok",
                                        "data": v
                                    });
                                },
                                Err(v) => {
                                    resp = json!({
                                        "status": "error",
                                        "error": v
                                    });
                                }
                            };
                        } else {
                            resp = json!({
                                "status": "error",
                                "error": "missing or invalid address"
                            });
                        }
                    } else {
                        resp = json!({
                            "status": "error",
                            "error": "missing or invalid address"
                        });
                    }
                }
            } else {
                resp = json!({
                    "status": "error",
                    "error": "missing or invalid oid field"
                });
            }
        } else {
            resp = json!({
                "status": "error",
                "error": "missing or invalid action"
            });
        }
        while socket.send_str(&resp.to_string(), 0).is_err() {}
    }

}
