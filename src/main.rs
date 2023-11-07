extern crate ton_bls_lib;
use ton_bls_lib::bls::*;

use rand::{RngCore, SeedableRng};
use std::time::{Instant, Duration};
use rand::Rng;
use std::collections::HashSet;
use std::{ptr, slice};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;


pub fn generate_random_msg() -> Vec<u8> {
    let msg_len = rand::thread_rng().gen_range(2, 100);
    println!("Msg len = {}", msg_len);
    let mut msg = vec![0u8; msg_len as usize];
    rand::thread_rng().fill_bytes(&mut msg);
    println!("Msg:");
    println!("{:?}", msg);
    msg
}

fn print(kp: &([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])) {
    println!("--------------------------------------------------");
    println!("BLS key pair:");
    println!("--------------------------------------------------");
    println!("Secret key bytes:");
    println!("{:?}", kp.1);
    println!("Secret key len: {}", kp.1.len());
    println!("Public key bytes:");
    println!("{:?}", kp.0);
    println!("Public key len: {}", kp.0.len());
    println!("--------------------------------------------------");
}

fn sign(sk: &[u8; BLS_SECRET_KEY_LEN], msg: &Vec<u8>, total_num_of_nodes: u16, index: u16) -> Vec<u8> {
    let sig_bytes = ton_bls_lib::bls::sign(sk, msg).unwrap();
    println!("Signature bytes:");
    println!("{:?}", sig_bytes);
    println!("Signature len: {}", sig_bytes.len());

    let bls_sig_bytes = add_node_info_to_sig(sig_bytes, index, total_num_of_nodes).unwrap();
    println!("BLS wrapped signature bytes:");
    println!("{:?}", bls_sig_bytes);
    println!("Wrapped signature len: {}", bls_sig_bytes.len());
    bls_sig_bytes
}

fn main() {
    let kp_1 = gen_bls_key_pair().unwrap();
    print(&kp_1);
    let kp_2 = gen_bls_key_pair().unwrap();
    print(&kp_2);

    let msg = generate_random_msg();

    let total_num_of_nodes = 5;
    let ind_1 = 3;
    let ind_2 = 0;

    let bls_sig_1 = sign(&kp_1.1, &msg, total_num_of_nodes, ind_1);
    let bls_sig_2 = sign(&kp_2.1, &msg, total_num_of_nodes, ind_2);

    let mut pks_refs = Vec::new();
    pks_refs.push(&kp_1.0);
    pks_refs.push(&kp_2.0);

    let apk = aggregate_public_keys(&pks_refs).unwrap();

    println!("Aggregated Public key bytes:");
    println!("{:?}", apk);
    println!("Public key len: {}", apk.len());
    println!("--------------------------------------------------");

    let agg_sig = aggregate_two_bls_signatures(&bls_sig_1, &bls_sig_2).unwrap();

    println!("Aggregated BLS signature bytes:");
    println!("{:?}", agg_sig);
    println!("Aggregated signature len: {}", agg_sig.len());

    let res = truncate_nodes_info_and_verify(&agg_sig, &apk, &msg).unwrap();
    println!("res = {:?}", res);
}
