#![feature(rustc_private)]

extern crate rustc;
use rustc::util::sha2::{Digest,Sha256};
use std::u8;

fn main() {
	let r2: Vec<u8> = {
		let mut hash = Sha256::new();
		hash.input("test1".as_ref());
		hash.result_bytes()
	};
	let x: Vec<u8> = {
		let mut hash = Sha256::new();
		hash.input("test2".as_ref());
		hash.result_bytes()
	};
	let r1 = {
		let mut v = vec![];
		for (a, b) in r2.iter().zip(x.iter()) {
			v.push(a ^ b);
		}

		v
	};

	let h1: Vec<u8> = {
		let mut hash = Sha256::new();
		hash.input(&r1);
		hash.result_bytes()
	};

	let h2: Vec<u8> = {
		let mut hash = Sha256::new();
		hash.input(&r2);
		hash.result_bytes()
	};

	print!("std::vector<bool> h1 = "); into_bin(&h1);
	print!("std::vector<bool> h2 = "); into_bin(&h2);
	print!("std::vector<bool> x = "); into_bin(&x);
	print!("std::vector<bool> r1 = "); into_bin(&r1);
	print!("std::vector<bool> r2 = "); into_bin(&r2);
}

fn into_bin(a: &Vec<u8>) {
	let mut first = true;
	print!("{{");
	for a in a.iter() {
		print!("{}{}, {}, {}, {}, {}, {}, {}, {}",
			{if (!first) { ", " } else {first = false; ""}},
			{a & (2u8.pow(7)) > 0},
			{a & (2u8.pow(6)) > 0},
			{a & (2u8.pow(5)) > 0},
			{a & (2u8.pow(4)) > 0},
			{a & (2u8.pow(3)) > 0},
			{a & (2u8.pow(2)) > 0},
			{a & (2u8.pow(1)) > 0},
			{a & (2u8.pow(0)) > 0});
	}
	println!("}};");
/*
	for a in a.iter() {
		print!("{:02x}", a);
	}

	println!("");
*/
}