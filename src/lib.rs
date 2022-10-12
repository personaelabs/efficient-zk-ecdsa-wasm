use console_error_panic_hook;
use hex::FromHex;
use libsecp256k1::{PublicKey, SecretKey};
use num_bigint::BigUint;
use serde;
use serde::{Deserialize, Serialize};
use std::ops::Mul;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

mod constants;

#[derive(Serialize, Deserialize)]
struct Powers {
    powers: Vec<Vec<Vec<Vec<String>>>>,
}

#[wasm_bindgen]
// Compute the powers of the give point and return a JSON of the powers
pub fn compute_powers(point_row: String) -> String {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    let point_in_bytes = <[u8; 65]>::from_hex(point_row).unwrap();

    let curve_n = BigUint::parse_bytes(
        b"115792089237316195423570985008687907853269984665640564039457584007908834671663",
        10,
    )
    .unwrap();
    let point = PublicKey::parse(&point_in_bytes).unwrap();

    // Representing the powers in vectors because I couldn't figure out how JSON stringify a 4D array.
    let mut powers: Vec<Vec<Vec<Vec<String>>>> =
        vec![vec![vec![vec!["0".to_string(); 4]; 2]; 256]; 32];

    for i in 0..constants::NUM_STRIDES {
        let exponent = BigUint::from(i * constants::STRIDE);
        // power = 2^(i * STRIDE) mod curve_n
        let power = BigUint::from(2 as u32).modpow(&exponent, &curve_n);

        for j in 0..((2 as u32).pow(constants::STRIDE)) {
            // l = 2^(i * STRIDE) * j mod curve_n
            let l = power.clone().mul(BigUint::from(j));

            // If l == 0, we just set the power to [[0,0,0,0], [0,0,0,0]]
            if l == BigUint::from(0 as u32) {
                for k in 0..4 {
                    powers[i as usize][j as usize][0][k] = String::from("0");
                    powers[i as usize][j as usize][1][k] = String::from("0");
                }
            } else {
                let mut l_as_bytes = l.to_bytes_le();
                l_as_bytes.resize(32, 0);
                l_as_bytes.reverse();

                let l_as_secret_key = SecretKey::parse_slice(&l_as_bytes).unwrap();

                // point_power = l * point
                let mut point_power = point.clone();
                point_power.tweak_mul_assign(&l_as_secret_key).unwrap();

                let point_power_in_bytes = point_power.serialize();
                let point_power_x = &point_power_in_bytes[1..33];
                let point_power_y = &point_power_in_bytes[33..65];

                for k in 0..4 {
                    let x_register: [u8; 8] =
                        point_power_x[k * 8..((k + 1) * 8)].try_into().unwrap();
                    let y_register: [u8; 8] =
                        point_power_y[k * 8..((k + 1) * 8)].try_into().unwrap();

                    powers[i as usize][j as usize][0][3 - k] =
                        u64::from_be_bytes(x_register).to_string();
                    powers[i as usize][j as usize][1][3 - k] =
                        u64::from_be_bytes(y_register).to_string();
                }
            }
        }
    }

    // Stringify the powers and return it
    serde_json::to_string(&(Powers { powers })).unwrap()
}

fn sum_powers(powers: &Vec<Vec<Vec<u64>>>) -> PublicKey {
    let mut pub_keys: Vec<PublicKey> = Vec::new();

    // Turn byte representation of the points to PublicKey
    for power in powers.iter() {
        // Big endian representation of the x and y coordinates
        let mut bytes: [u8; 65] = [0; 65];

        // Assign each byte of the x coordinate
        let power_x = &power[0];
        for (j, register) in power_x.iter().rev().enumerate() {
            // Assign each byte to the bytes slice
            for (k, byte) in register.to_be_bytes().iter().enumerate() {
                bytes[1 + k + j * 8] = *byte;
            }
        }

        // Assign each byte of the y coordinate
        let power_y = &power[1];
        for (j, register) in power_y.iter().rev().enumerate() {
            // Assign each byte to the bytes slice
            for (k, byte) in register.to_be_bytes().iter().enumerate() {
                bytes[33 + (k + j * 8)] = *byte;
            }
        }

        // If all bytes are 0 don't add
        if !bytes.iter().any(|&byte| byte != 0) {
            continue;
        }

        // Set the prefix
        bytes[0] = 0x04;

        let pub_key = PublicKey::parse(&bytes).unwrap();
        pub_keys.push(pub_key);
    }

    PublicKey::combine(&pub_keys).unwrap()
}

#[wasm_bindgen]
// For each of the 32 strides
// 1. sum the points and multiply by a certain value
// 2. multiply the sum by a certain value
// 3. check that the multiplied result equals to the original point
// Better to check the points are in the correct order as well?
// For example
// - The first "row" of the powers: P0_i = 2^0 * i * P  \in i=0..255
// - sum(P0_i) = (2^0 * 0 * P) + (2^0 * 1 * P) + ... + (2^0 * 255 * P)
// - P = (2^0 * 0 + ... + 2^0 * 255)^-1 * sum(P0_i)
pub fn verify_powers(point: String, powers: String) -> bool {
    // Transform powers in string JSON representation into a 4D vector of u64
    let powers_as_u64s: Powers = serde_json::from_str(&powers).unwrap();
    let point_as_bytes = <[u8; 65]>::from_hex(point).unwrap();

    let point_as_public_key = PublicKey::parse(&point_as_bytes).unwrap();

    for (i, row) in powers_as_u64s.powers.iter().enumerate() {
        let powers_as_u64s = row
            .iter()
            .map(|coordinates| {
                coordinates
                    .iter()
                    .map(|registers| {
                        registers
                            .iter()
                            .map(|register| u64::from_str_radix(register, 10).unwrap())
                            .collect::<Vec<u64>>()
                    })
                    .collect::<Vec<Vec<u64>>>()
            })
            .collect::<Vec<Vec<Vec<u64>>>>();

        let mut sum = sum_powers(&powers_as_u64s);

        // Could hard code the byte representation
        let mut mul_by = BigUint::from_str(&constants::mults[i])
            .unwrap()
            .to_bytes_le();
        mul_by.resize(32, 0);
        mul_by.reverse();

        sum.tweak_mul_assign(&SecretKey::parse_slice(&mul_by).unwrap())
            .unwrap();

        // Check if the summed points equal to the original point
        if sum.ne(&point_as_public_key) {
            return false;
        }
    }

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_compute_powers() {
        // Test using the generator point of secp256k1 for convenience in debugging
        let point = constants::SECP256K1_G;
        // For now, just check if this runs without panicking
        compute_powers(point.to_string());
    }

    #[test]
    fn test_verify_powers() {
        let point = constants::SECP256K1_G;
        let powers = compute_powers(point.to_string());

        let result = verify_powers(point.to_string(), powers);
        assert_eq!(result, true);
    }
}
