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

                let resp_values = snmp_querier::walk_oid(agent_addr, community, oid_slice);

                //let resp_values: Vec<serde_json::Value> = Vec::new();
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
