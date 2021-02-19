use fxhash::FxHashSet;

use crate::domain::InvalidDomain;
use crate::domain::DOMAIN_MAX_LENGTH;
use crate::Domain;

use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};

trait DomainSetSingle: Send + Sync {
    fn wrapper_contains(&self, domain: &[u8]) -> bool;
    fn wrapper_insert(&mut self, domain: &[u8]) -> bool;
    fn wrapper_remove(&mut self, domain: &[u8]) -> bool;
    fn wrapper_into_iter(self: Box<Self>) -> Box<dyn Iterator<Item = Domain>>;
    fn wrapper_iter(&self) -> Box<dyn Iterator<Item = Domain> + '_>;
    fn wrapper_shrink_to_fit(&mut self);
    fn wrapper_len(&self) -> usize;
    fn wrapper_is_empty(&self) -> bool;
}

macro_rules! implement_domain_set_single {
    ($n: expr) => {
        impl DomainSetSingle for FxHashSet<[u8; $n]> {
            fn wrapper_contains(&self, domain: &[u8]) -> bool {
                let mut domain_array = [0; $n];
                domain_array.copy_from_slice(domain);
                self.contains(&domain_array)
            }
            fn wrapper_insert(&mut self, domain: &[u8]) -> bool {
                let mut domain_array = [0; $n];
                domain_array.copy_from_slice(domain);
                self.insert(domain_array)
            }
            fn wrapper_remove(&mut self, domain: &[u8]) -> bool {
                let mut domain_array = [0; $n];
                domain_array.copy_from_slice(domain);
                self.remove(&domain_array)
            }
            fn wrapper_into_iter(self: Box<Self>) -> Box<dyn Iterator<Item = Domain>> {
                Box::new(self.into_iter().flat_map(|domain| {
                    std::str::from_utf8(&domain)
                        .ok()
                        .map(|domain| Domain::from_str_unchecked(domain))
                }))
            }
            fn wrapper_iter(&self) -> Box<dyn Iterator<Item = Domain> + '_> {
                Box::new(self.iter().flat_map(|domain| {
                    std::str::from_utf8(domain)
                        .ok()
                        .map(|domain| Domain::from_str_unchecked(domain))
                }))
            }
            fn wrapper_shrink_to_fit(&mut self) {
                self.shrink_to_fit()
            }
            fn wrapper_len(&self) -> usize {
                self.len()
            }
            fn wrapper_is_empty(&self) -> bool {
                self.is_empty()
            }
        }
    };
}

mod domain_set_implementations {
    use super::*;
    implement_domain_set_single!(0);
    implement_domain_set_single!(1);
    implement_domain_set_single!(2);
    implement_domain_set_single!(3);
    implement_domain_set_single!(4);
    implement_domain_set_single!(5);
    implement_domain_set_single!(6);
    implement_domain_set_single!(7);
    implement_domain_set_single!(8);
    implement_domain_set_single!(9);
    implement_domain_set_single!(10);
    implement_domain_set_single!(11);
    implement_domain_set_single!(12);
    implement_domain_set_single!(13);
    implement_domain_set_single!(14);
    implement_domain_set_single!(15);
    implement_domain_set_single!(16);
    implement_domain_set_single!(17);
    implement_domain_set_single!(18);
    implement_domain_set_single!(19);
    implement_domain_set_single!(20);
    implement_domain_set_single!(21);
    implement_domain_set_single!(22);
    implement_domain_set_single!(23);
    implement_domain_set_single!(24);
    implement_domain_set_single!(25);
    implement_domain_set_single!(26);
    implement_domain_set_single!(27);
    implement_domain_set_single!(28);
    implement_domain_set_single!(29);
    implement_domain_set_single!(30);
    implement_domain_set_single!(31);
    implement_domain_set_single!(32);
    implement_domain_set_single!(33);
    implement_domain_set_single!(34);
    implement_domain_set_single!(35);
    implement_domain_set_single!(36);
    implement_domain_set_single!(37);
    implement_domain_set_single!(38);
    implement_domain_set_single!(39);
    implement_domain_set_single!(40);
    implement_domain_set_single!(41);
    implement_domain_set_single!(42);
    implement_domain_set_single!(43);
    implement_domain_set_single!(44);
    implement_domain_set_single!(45);
    implement_domain_set_single!(46);
    implement_domain_set_single!(47);
    implement_domain_set_single!(48);
    implement_domain_set_single!(49);
    implement_domain_set_single!(50);
    implement_domain_set_single!(51);
    implement_domain_set_single!(52);
    implement_domain_set_single!(53);
    implement_domain_set_single!(54);
    implement_domain_set_single!(55);
    implement_domain_set_single!(56);
    implement_domain_set_single!(57);
    implement_domain_set_single!(58);
    implement_domain_set_single!(59);
    implement_domain_set_single!(60);
    implement_domain_set_single!(61);
    implement_domain_set_single!(62);
    implement_domain_set_single!(63);
    implement_domain_set_single!(64);
    implement_domain_set_single!(65);
    implement_domain_set_single!(66);
    implement_domain_set_single!(67);
    implement_domain_set_single!(68);
    implement_domain_set_single!(69);
    implement_domain_set_single!(70);
    implement_domain_set_single!(71);
    implement_domain_set_single!(72);
    implement_domain_set_single!(73);
    implement_domain_set_single!(74);
    implement_domain_set_single!(75);
    implement_domain_set_single!(76);
    implement_domain_set_single!(77);
    implement_domain_set_single!(78);
    implement_domain_set_single!(79);
    implement_domain_set_single!(80);
    implement_domain_set_single!(81);
    implement_domain_set_single!(82);
    implement_domain_set_single!(83);
    implement_domain_set_single!(84);
    implement_domain_set_single!(85);
    implement_domain_set_single!(86);
    implement_domain_set_single!(87);
    implement_domain_set_single!(88);
    implement_domain_set_single!(89);
    implement_domain_set_single!(90);
    implement_domain_set_single!(91);
    implement_domain_set_single!(92);
    implement_domain_set_single!(93);
    implement_domain_set_single!(94);
    implement_domain_set_single!(95);
    implement_domain_set_single!(96);
    implement_domain_set_single!(97);
    implement_domain_set_single!(98);
    implement_domain_set_single!(99);
    implement_domain_set_single!(100);
    implement_domain_set_single!(101);
    implement_domain_set_single!(102);
    implement_domain_set_single!(103);
    implement_domain_set_single!(104);
    implement_domain_set_single!(105);
    implement_domain_set_single!(106);
    implement_domain_set_single!(107);
    implement_domain_set_single!(108);
    implement_domain_set_single!(109);
    implement_domain_set_single!(110);
    implement_domain_set_single!(111);
    implement_domain_set_single!(112);
    implement_domain_set_single!(113);
    implement_domain_set_single!(114);
    implement_domain_set_single!(115);
    implement_domain_set_single!(116);
    implement_domain_set_single!(117);
    implement_domain_set_single!(118);
    implement_domain_set_single!(119);
    implement_domain_set_single!(120);
    implement_domain_set_single!(121);
    implement_domain_set_single!(122);
    implement_domain_set_single!(123);
    implement_domain_set_single!(124);
    implement_domain_set_single!(125);
    implement_domain_set_single!(126);
    implement_domain_set_single!(127);
    implement_domain_set_single!(128);
    implement_domain_set_single!(129);
    implement_domain_set_single!(130);
    implement_domain_set_single!(131);
    implement_domain_set_single!(132);
    implement_domain_set_single!(133);
    implement_domain_set_single!(134);
    implement_domain_set_single!(135);
    implement_domain_set_single!(136);
    implement_domain_set_single!(137);
    implement_domain_set_single!(138);
    implement_domain_set_single!(139);
    implement_domain_set_single!(140);
    implement_domain_set_single!(141);
    implement_domain_set_single!(142);
    implement_domain_set_single!(143);
    implement_domain_set_single!(144);
    implement_domain_set_single!(145);
    implement_domain_set_single!(146);
    implement_domain_set_single!(147);
    implement_domain_set_single!(148);
    implement_domain_set_single!(149);
    implement_domain_set_single!(150);
    implement_domain_set_single!(151);
    implement_domain_set_single!(152);
    implement_domain_set_single!(153);
    implement_domain_set_single!(154);
    implement_domain_set_single!(155);
    implement_domain_set_single!(156);
    implement_domain_set_single!(157);
    implement_domain_set_single!(158);
    implement_domain_set_single!(159);
    implement_domain_set_single!(160);
    implement_domain_set_single!(161);
    implement_domain_set_single!(162);
    implement_domain_set_single!(163);
    implement_domain_set_single!(164);
    implement_domain_set_single!(165);
    implement_domain_set_single!(166);
    implement_domain_set_single!(167);
    implement_domain_set_single!(168);
    implement_domain_set_single!(169);
    implement_domain_set_single!(170);
    implement_domain_set_single!(171);
    implement_domain_set_single!(172);
    implement_domain_set_single!(173);
    implement_domain_set_single!(174);
    implement_domain_set_single!(175);
    implement_domain_set_single!(176);
    implement_domain_set_single!(177);
    implement_domain_set_single!(178);
    implement_domain_set_single!(179);
    implement_domain_set_single!(180);
    implement_domain_set_single!(181);
    implement_domain_set_single!(182);
    implement_domain_set_single!(183);
    implement_domain_set_single!(184);
    implement_domain_set_single!(185);
    implement_domain_set_single!(186);
    implement_domain_set_single!(187);
    implement_domain_set_single!(188);
    implement_domain_set_single!(189);
    implement_domain_set_single!(190);
    implement_domain_set_single!(191);
    implement_domain_set_single!(192);
    implement_domain_set_single!(193);
    implement_domain_set_single!(194);
    implement_domain_set_single!(195);
    implement_domain_set_single!(196);
    implement_domain_set_single!(197);
    implement_domain_set_single!(198);
    implement_domain_set_single!(199);
    implement_domain_set_single!(200);
    implement_domain_set_single!(201);
    implement_domain_set_single!(202);
    implement_domain_set_single!(203);
    implement_domain_set_single!(204);
    implement_domain_set_single!(205);
    implement_domain_set_single!(206);
    implement_domain_set_single!(207);
    implement_domain_set_single!(208);
    implement_domain_set_single!(209);
    implement_domain_set_single!(210);
    implement_domain_set_single!(211);
    implement_domain_set_single!(212);
    implement_domain_set_single!(213);
    implement_domain_set_single!(214);
    implement_domain_set_single!(215);
    implement_domain_set_single!(216);
    implement_domain_set_single!(217);
    implement_domain_set_single!(218);
    implement_domain_set_single!(219);
    implement_domain_set_single!(220);
    implement_domain_set_single!(221);
    implement_domain_set_single!(222);
    implement_domain_set_single!(223);
    implement_domain_set_single!(224);
    implement_domain_set_single!(225);
    implement_domain_set_single!(226);
    implement_domain_set_single!(227);
    implement_domain_set_single!(228);
    implement_domain_set_single!(229);
    implement_domain_set_single!(230);
    implement_domain_set_single!(231);
    implement_domain_set_single!(232);
    implement_domain_set_single!(233);
    implement_domain_set_single!(234);
    implement_domain_set_single!(235);
    implement_domain_set_single!(236);
    implement_domain_set_single!(237);
    implement_domain_set_single!(238);
    implement_domain_set_single!(239);
    implement_domain_set_single!(240);
    implement_domain_set_single!(241);
    implement_domain_set_single!(242);
    implement_domain_set_single!(243);
    implement_domain_set_single!(244);
    implement_domain_set_single!(245);
    implement_domain_set_single!(246);
    implement_domain_set_single!(247);
    implement_domain_set_single!(248);
    implement_domain_set_single!(249);
    implement_domain_set_single!(250);
    implement_domain_set_single!(251);
    implement_domain_set_single!(252);
    implement_domain_set_single!(253);
}

pub struct DomainSetIntoIter {
    sub_sets: Vec<Box<dyn DomainSetSingle>>,
    current_iterator: Option<Box<dyn Iterator<Item = Domain> + 'static>>,
}

impl DomainSetIntoIter {
    fn new(mut domain_set: DomainSet) -> Self {
        let mut sub_sets: Vec<Box<dyn DomainSetSingle>> = Vec::new();
        for i in 0..domain_set.sub_sets.len() {
            let mut dummy: Box<dyn DomainSetSingle> = Box::new(FxHashSet::<[u8; 0]>::default());
            std::mem::swap(&mut dummy, domain_set.sub_sets.get_mut(i).unwrap());
            sub_sets.push(dummy);
        }
        Self {
            sub_sets,
            current_iterator: None,
        }
    }
}

impl Iterator for DomainSetIntoIter {
    type Item = Domain;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current_iterator) = &mut self.current_iterator {
            if let Some(output) = current_iterator.next() {
                return Some(output);
            }
        }
        if let Some(next_iterator) = self.sub_sets.pop() {
            let next_iterator = next_iterator.wrapper_into_iter();
            let mut next_iterator = Some(next_iterator);
            std::mem::swap(&mut next_iterator, &mut self.current_iterator);
            if self.sub_sets.is_empty() {
                self.sub_sets.shrink_to_fit();
            }
            self.next()
        } else {
            None
        }
    }
}

pub struct DomainSet {
    sub_sets: [Box<dyn DomainSetSingle>; DOMAIN_MAX_LENGTH + 1],
}

impl Default for DomainSet {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainSet {
    pub fn new() -> Self {
        Self {
            sub_sets: [
                Box::new(FxHashSet::<[u8; 0]>::default()),
                Box::new(FxHashSet::<[u8; 1]>::default()),
                Box::new(FxHashSet::<[u8; 2]>::default()),
                Box::new(FxHashSet::<[u8; 3]>::default()),
                Box::new(FxHashSet::<[u8; 4]>::default()),
                Box::new(FxHashSet::<[u8; 5]>::default()),
                Box::new(FxHashSet::<[u8; 6]>::default()),
                Box::new(FxHashSet::<[u8; 7]>::default()),
                Box::new(FxHashSet::<[u8; 8]>::default()),
                Box::new(FxHashSet::<[u8; 9]>::default()),
                Box::new(FxHashSet::<[u8; 10]>::default()),
                Box::new(FxHashSet::<[u8; 11]>::default()),
                Box::new(FxHashSet::<[u8; 12]>::default()),
                Box::new(FxHashSet::<[u8; 13]>::default()),
                Box::new(FxHashSet::<[u8; 14]>::default()),
                Box::new(FxHashSet::<[u8; 15]>::default()),
                Box::new(FxHashSet::<[u8; 16]>::default()),
                Box::new(FxHashSet::<[u8; 17]>::default()),
                Box::new(FxHashSet::<[u8; 18]>::default()),
                Box::new(FxHashSet::<[u8; 19]>::default()),
                Box::new(FxHashSet::<[u8; 20]>::default()),
                Box::new(FxHashSet::<[u8; 21]>::default()),
                Box::new(FxHashSet::<[u8; 22]>::default()),
                Box::new(FxHashSet::<[u8; 23]>::default()),
                Box::new(FxHashSet::<[u8; 24]>::default()),
                Box::new(FxHashSet::<[u8; 25]>::default()),
                Box::new(FxHashSet::<[u8; 26]>::default()),
                Box::new(FxHashSet::<[u8; 27]>::default()),
                Box::new(FxHashSet::<[u8; 28]>::default()),
                Box::new(FxHashSet::<[u8; 29]>::default()),
                Box::new(FxHashSet::<[u8; 30]>::default()),
                Box::new(FxHashSet::<[u8; 31]>::default()),
                Box::new(FxHashSet::<[u8; 32]>::default()),
                Box::new(FxHashSet::<[u8; 33]>::default()),
                Box::new(FxHashSet::<[u8; 34]>::default()),
                Box::new(FxHashSet::<[u8; 35]>::default()),
                Box::new(FxHashSet::<[u8; 36]>::default()),
                Box::new(FxHashSet::<[u8; 37]>::default()),
                Box::new(FxHashSet::<[u8; 38]>::default()),
                Box::new(FxHashSet::<[u8; 39]>::default()),
                Box::new(FxHashSet::<[u8; 40]>::default()),
                Box::new(FxHashSet::<[u8; 41]>::default()),
                Box::new(FxHashSet::<[u8; 42]>::default()),
                Box::new(FxHashSet::<[u8; 43]>::default()),
                Box::new(FxHashSet::<[u8; 44]>::default()),
                Box::new(FxHashSet::<[u8; 45]>::default()),
                Box::new(FxHashSet::<[u8; 46]>::default()),
                Box::new(FxHashSet::<[u8; 47]>::default()),
                Box::new(FxHashSet::<[u8; 48]>::default()),
                Box::new(FxHashSet::<[u8; 49]>::default()),
                Box::new(FxHashSet::<[u8; 50]>::default()),
                Box::new(FxHashSet::<[u8; 51]>::default()),
                Box::new(FxHashSet::<[u8; 52]>::default()),
                Box::new(FxHashSet::<[u8; 53]>::default()),
                Box::new(FxHashSet::<[u8; 54]>::default()),
                Box::new(FxHashSet::<[u8; 55]>::default()),
                Box::new(FxHashSet::<[u8; 56]>::default()),
                Box::new(FxHashSet::<[u8; 57]>::default()),
                Box::new(FxHashSet::<[u8; 58]>::default()),
                Box::new(FxHashSet::<[u8; 59]>::default()),
                Box::new(FxHashSet::<[u8; 60]>::default()),
                Box::new(FxHashSet::<[u8; 61]>::default()),
                Box::new(FxHashSet::<[u8; 62]>::default()),
                Box::new(FxHashSet::<[u8; 63]>::default()),
                Box::new(FxHashSet::<[u8; 64]>::default()),
                Box::new(FxHashSet::<[u8; 65]>::default()),
                Box::new(FxHashSet::<[u8; 66]>::default()),
                Box::new(FxHashSet::<[u8; 67]>::default()),
                Box::new(FxHashSet::<[u8; 68]>::default()),
                Box::new(FxHashSet::<[u8; 69]>::default()),
                Box::new(FxHashSet::<[u8; 70]>::default()),
                Box::new(FxHashSet::<[u8; 71]>::default()),
                Box::new(FxHashSet::<[u8; 72]>::default()),
                Box::new(FxHashSet::<[u8; 73]>::default()),
                Box::new(FxHashSet::<[u8; 74]>::default()),
                Box::new(FxHashSet::<[u8; 75]>::default()),
                Box::new(FxHashSet::<[u8; 76]>::default()),
                Box::new(FxHashSet::<[u8; 77]>::default()),
                Box::new(FxHashSet::<[u8; 78]>::default()),
                Box::new(FxHashSet::<[u8; 79]>::default()),
                Box::new(FxHashSet::<[u8; 80]>::default()),
                Box::new(FxHashSet::<[u8; 81]>::default()),
                Box::new(FxHashSet::<[u8; 82]>::default()),
                Box::new(FxHashSet::<[u8; 83]>::default()),
                Box::new(FxHashSet::<[u8; 84]>::default()),
                Box::new(FxHashSet::<[u8; 85]>::default()),
                Box::new(FxHashSet::<[u8; 86]>::default()),
                Box::new(FxHashSet::<[u8; 87]>::default()),
                Box::new(FxHashSet::<[u8; 88]>::default()),
                Box::new(FxHashSet::<[u8; 89]>::default()),
                Box::new(FxHashSet::<[u8; 90]>::default()),
                Box::new(FxHashSet::<[u8; 91]>::default()),
                Box::new(FxHashSet::<[u8; 92]>::default()),
                Box::new(FxHashSet::<[u8; 93]>::default()),
                Box::new(FxHashSet::<[u8; 94]>::default()),
                Box::new(FxHashSet::<[u8; 95]>::default()),
                Box::new(FxHashSet::<[u8; 96]>::default()),
                Box::new(FxHashSet::<[u8; 97]>::default()),
                Box::new(FxHashSet::<[u8; 98]>::default()),
                Box::new(FxHashSet::<[u8; 99]>::default()),
                Box::new(FxHashSet::<[u8; 100]>::default()),
                Box::new(FxHashSet::<[u8; 101]>::default()),
                Box::new(FxHashSet::<[u8; 102]>::default()),
                Box::new(FxHashSet::<[u8; 103]>::default()),
                Box::new(FxHashSet::<[u8; 104]>::default()),
                Box::new(FxHashSet::<[u8; 105]>::default()),
                Box::new(FxHashSet::<[u8; 106]>::default()),
                Box::new(FxHashSet::<[u8; 107]>::default()),
                Box::new(FxHashSet::<[u8; 108]>::default()),
                Box::new(FxHashSet::<[u8; 109]>::default()),
                Box::new(FxHashSet::<[u8; 110]>::default()),
                Box::new(FxHashSet::<[u8; 111]>::default()),
                Box::new(FxHashSet::<[u8; 112]>::default()),
                Box::new(FxHashSet::<[u8; 113]>::default()),
                Box::new(FxHashSet::<[u8; 114]>::default()),
                Box::new(FxHashSet::<[u8; 115]>::default()),
                Box::new(FxHashSet::<[u8; 116]>::default()),
                Box::new(FxHashSet::<[u8; 117]>::default()),
                Box::new(FxHashSet::<[u8; 118]>::default()),
                Box::new(FxHashSet::<[u8; 119]>::default()),
                Box::new(FxHashSet::<[u8; 120]>::default()),
                Box::new(FxHashSet::<[u8; 121]>::default()),
                Box::new(FxHashSet::<[u8; 122]>::default()),
                Box::new(FxHashSet::<[u8; 123]>::default()),
                Box::new(FxHashSet::<[u8; 124]>::default()),
                Box::new(FxHashSet::<[u8; 125]>::default()),
                Box::new(FxHashSet::<[u8; 126]>::default()),
                Box::new(FxHashSet::<[u8; 127]>::default()),
                Box::new(FxHashSet::<[u8; 128]>::default()),
                Box::new(FxHashSet::<[u8; 129]>::default()),
                Box::new(FxHashSet::<[u8; 130]>::default()),
                Box::new(FxHashSet::<[u8; 131]>::default()),
                Box::new(FxHashSet::<[u8; 132]>::default()),
                Box::new(FxHashSet::<[u8; 133]>::default()),
                Box::new(FxHashSet::<[u8; 134]>::default()),
                Box::new(FxHashSet::<[u8; 135]>::default()),
                Box::new(FxHashSet::<[u8; 136]>::default()),
                Box::new(FxHashSet::<[u8; 137]>::default()),
                Box::new(FxHashSet::<[u8; 138]>::default()),
                Box::new(FxHashSet::<[u8; 139]>::default()),
                Box::new(FxHashSet::<[u8; 140]>::default()),
                Box::new(FxHashSet::<[u8; 141]>::default()),
                Box::new(FxHashSet::<[u8; 142]>::default()),
                Box::new(FxHashSet::<[u8; 143]>::default()),
                Box::new(FxHashSet::<[u8; 144]>::default()),
                Box::new(FxHashSet::<[u8; 145]>::default()),
                Box::new(FxHashSet::<[u8; 146]>::default()),
                Box::new(FxHashSet::<[u8; 147]>::default()),
                Box::new(FxHashSet::<[u8; 148]>::default()),
                Box::new(FxHashSet::<[u8; 149]>::default()),
                Box::new(FxHashSet::<[u8; 150]>::default()),
                Box::new(FxHashSet::<[u8; 151]>::default()),
                Box::new(FxHashSet::<[u8; 152]>::default()),
                Box::new(FxHashSet::<[u8; 153]>::default()),
                Box::new(FxHashSet::<[u8; 154]>::default()),
                Box::new(FxHashSet::<[u8; 155]>::default()),
                Box::new(FxHashSet::<[u8; 156]>::default()),
                Box::new(FxHashSet::<[u8; 157]>::default()),
                Box::new(FxHashSet::<[u8; 158]>::default()),
                Box::new(FxHashSet::<[u8; 159]>::default()),
                Box::new(FxHashSet::<[u8; 160]>::default()),
                Box::new(FxHashSet::<[u8; 161]>::default()),
                Box::new(FxHashSet::<[u8; 162]>::default()),
                Box::new(FxHashSet::<[u8; 163]>::default()),
                Box::new(FxHashSet::<[u8; 164]>::default()),
                Box::new(FxHashSet::<[u8; 165]>::default()),
                Box::new(FxHashSet::<[u8; 166]>::default()),
                Box::new(FxHashSet::<[u8; 167]>::default()),
                Box::new(FxHashSet::<[u8; 168]>::default()),
                Box::new(FxHashSet::<[u8; 169]>::default()),
                Box::new(FxHashSet::<[u8; 170]>::default()),
                Box::new(FxHashSet::<[u8; 171]>::default()),
                Box::new(FxHashSet::<[u8; 172]>::default()),
                Box::new(FxHashSet::<[u8; 173]>::default()),
                Box::new(FxHashSet::<[u8; 174]>::default()),
                Box::new(FxHashSet::<[u8; 175]>::default()),
                Box::new(FxHashSet::<[u8; 176]>::default()),
                Box::new(FxHashSet::<[u8; 177]>::default()),
                Box::new(FxHashSet::<[u8; 178]>::default()),
                Box::new(FxHashSet::<[u8; 179]>::default()),
                Box::new(FxHashSet::<[u8; 180]>::default()),
                Box::new(FxHashSet::<[u8; 181]>::default()),
                Box::new(FxHashSet::<[u8; 182]>::default()),
                Box::new(FxHashSet::<[u8; 183]>::default()),
                Box::new(FxHashSet::<[u8; 184]>::default()),
                Box::new(FxHashSet::<[u8; 185]>::default()),
                Box::new(FxHashSet::<[u8; 186]>::default()),
                Box::new(FxHashSet::<[u8; 187]>::default()),
                Box::new(FxHashSet::<[u8; 188]>::default()),
                Box::new(FxHashSet::<[u8; 189]>::default()),
                Box::new(FxHashSet::<[u8; 190]>::default()),
                Box::new(FxHashSet::<[u8; 191]>::default()),
                Box::new(FxHashSet::<[u8; 192]>::default()),
                Box::new(FxHashSet::<[u8; 193]>::default()),
                Box::new(FxHashSet::<[u8; 194]>::default()),
                Box::new(FxHashSet::<[u8; 195]>::default()),
                Box::new(FxHashSet::<[u8; 196]>::default()),
                Box::new(FxHashSet::<[u8; 197]>::default()),
                Box::new(FxHashSet::<[u8; 198]>::default()),
                Box::new(FxHashSet::<[u8; 199]>::default()),
                Box::new(FxHashSet::<[u8; 200]>::default()),
                Box::new(FxHashSet::<[u8; 201]>::default()),
                Box::new(FxHashSet::<[u8; 202]>::default()),
                Box::new(FxHashSet::<[u8; 203]>::default()),
                Box::new(FxHashSet::<[u8; 204]>::default()),
                Box::new(FxHashSet::<[u8; 205]>::default()),
                Box::new(FxHashSet::<[u8; 206]>::default()),
                Box::new(FxHashSet::<[u8; 207]>::default()),
                Box::new(FxHashSet::<[u8; 208]>::default()),
                Box::new(FxHashSet::<[u8; 209]>::default()),
                Box::new(FxHashSet::<[u8; 210]>::default()),
                Box::new(FxHashSet::<[u8; 211]>::default()),
                Box::new(FxHashSet::<[u8; 212]>::default()),
                Box::new(FxHashSet::<[u8; 213]>::default()),
                Box::new(FxHashSet::<[u8; 214]>::default()),
                Box::new(FxHashSet::<[u8; 215]>::default()),
                Box::new(FxHashSet::<[u8; 216]>::default()),
                Box::new(FxHashSet::<[u8; 217]>::default()),
                Box::new(FxHashSet::<[u8; 218]>::default()),
                Box::new(FxHashSet::<[u8; 219]>::default()),
                Box::new(FxHashSet::<[u8; 220]>::default()),
                Box::new(FxHashSet::<[u8; 221]>::default()),
                Box::new(FxHashSet::<[u8; 222]>::default()),
                Box::new(FxHashSet::<[u8; 223]>::default()),
                Box::new(FxHashSet::<[u8; 224]>::default()),
                Box::new(FxHashSet::<[u8; 225]>::default()),
                Box::new(FxHashSet::<[u8; 226]>::default()),
                Box::new(FxHashSet::<[u8; 227]>::default()),
                Box::new(FxHashSet::<[u8; 228]>::default()),
                Box::new(FxHashSet::<[u8; 229]>::default()),
                Box::new(FxHashSet::<[u8; 230]>::default()),
                Box::new(FxHashSet::<[u8; 231]>::default()),
                Box::new(FxHashSet::<[u8; 232]>::default()),
                Box::new(FxHashSet::<[u8; 233]>::default()),
                Box::new(FxHashSet::<[u8; 234]>::default()),
                Box::new(FxHashSet::<[u8; 235]>::default()),
                Box::new(FxHashSet::<[u8; 236]>::default()),
                Box::new(FxHashSet::<[u8; 237]>::default()),
                Box::new(FxHashSet::<[u8; 238]>::default()),
                Box::new(FxHashSet::<[u8; 239]>::default()),
                Box::new(FxHashSet::<[u8; 240]>::default()),
                Box::new(FxHashSet::<[u8; 241]>::default()),
                Box::new(FxHashSet::<[u8; 242]>::default()),
                Box::new(FxHashSet::<[u8; 243]>::default()),
                Box::new(FxHashSet::<[u8; 244]>::default()),
                Box::new(FxHashSet::<[u8; 245]>::default()),
                Box::new(FxHashSet::<[u8; 246]>::default()),
                Box::new(FxHashSet::<[u8; 247]>::default()),
                Box::new(FxHashSet::<[u8; 248]>::default()),
                Box::new(FxHashSet::<[u8; 249]>::default()),
                Box::new(FxHashSet::<[u8; 250]>::default()),
                Box::new(FxHashSet::<[u8; 251]>::default()),
                Box::new(FxHashSet::<[u8; 252]>::default()),
                Box::new(FxHashSet::<[u8; 253]>::default()),
            ],
        }
    }

    pub fn contains(&self, domain: &Domain) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()].wrapper_contains(&domain_bytes)
    }
    pub fn insert(&mut self, domain: Domain) -> bool {
        self.insert_str_unchecked(&domain)
    }
    pub fn insert_str(&mut self, domain: &str) -> Result<bool, InvalidDomain> {
        Domain::str_is_valid_domain(domain)?;
        Ok(self.insert_str_unchecked(domain))
    }
    pub fn insert_str_unchecked(&mut self, domain: &str) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()].wrapper_insert(&domain_bytes)
    }
    pub fn remove(&mut self, domain: &Domain) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()].wrapper_remove(&domain_bytes)
    }
    pub fn iter(&self) -> impl Iterator<Item = Domain> + '_ {
        self.sub_sets
            .iter()
            .flat_map(|sub_set| sub_set.wrapper_iter())
    }
    pub fn shrink_to_fit(&mut self) {
        for sub_set in self.sub_sets.iter_mut() {
            sub_set.wrapper_shrink_to_fit();
        }
    }
    pub fn len(&self) -> usize {
        self.sub_sets
            .iter()
            .map(|sub_set| sub_set.wrapper_len())
            .sum()
    }
    pub fn is_empty(&self) -> bool {
        self.sub_sets
            .iter()
            .all(|sub_set| sub_set.wrapper_is_empty())
    }

    pub fn into_concurrent(mut self) -> DomainSetConcurrent {
        let mut concurrent_sub_sets: [MaybeUninit<Arc<Mutex<Box<dyn DomainSetSingle>>>>;
            DOMAIN_MAX_LENGTH + 1] = unsafe { MaybeUninit::uninit().assume_init() };
        for i in 0..=DOMAIN_MAX_LENGTH {
            let mut dummy: Box<dyn DomainSetSingle> = Box::new(FxHashSet::<[u8; 0]>::default());
            std::mem::swap(&mut dummy, self.sub_sets.get_mut(i).unwrap());
            concurrent_sub_sets[i] = MaybeUninit::new(Arc::new(Mutex::new(dummy)));
        }
        DomainSetConcurrent {
            sub_sets: unsafe { std::mem::transmute::<_, _>(concurrent_sub_sets) },
        }
    }
}

impl IntoIterator for DomainSet {
    type Item = Domain;
    type IntoIter = DomainSetIntoIter;
    fn into_iter(self) -> <Self as IntoIterator>::IntoIter {
        DomainSetIntoIter::new(self)
    }
}

#[derive(Clone)]
pub struct DomainSetConcurrent {
    sub_sets: [Arc<Mutex<Box<dyn DomainSetSingle>>>; DOMAIN_MAX_LENGTH + 1],
}

impl Default for DomainSetConcurrent {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainSetConcurrent {
    pub fn new() -> Self {
        DomainSet::new().into_concurrent()
    }

    pub fn contains(&self, domain: &Domain) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()]
            .lock()
            .unwrap()
            .wrapper_contains(&domain_bytes)
    }
    pub fn insert(&self, domain: Domain) -> bool {
        self.insert_str_unchecked(&domain)
    }
    pub fn insert_str(&self, domain: &str) -> Result<bool, InvalidDomain> {
        Domain::str_is_valid_domain(domain)?;
        Ok(self.insert_str_unchecked(domain))
    }
    pub fn insert_str_unchecked(&self, domain: &str) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()]
            .lock()
            .unwrap()
            .wrapper_insert(&domain_bytes)
    }
    pub fn remove(&self, domain: &Domain) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()]
            .lock()
            .unwrap()
            .wrapper_remove(&domain_bytes)
    }
    pub fn shrink_to_fit(&self) {
        for sub_set in self.sub_sets.iter() {
            sub_set.lock().unwrap().wrapper_shrink_to_fit();
        }
    }
    pub fn len(&self) -> usize {
        self.sub_sets
            .iter()
            .map(|sub_set| sub_set.lock().unwrap().wrapper_len())
            .sum()
    }
    pub fn is_empty(&self) -> bool {
        self.sub_sets
            .iter()
            .all(|sub_set| sub_set.lock().unwrap().wrapper_is_empty())
    }
    pub fn into_single_threaded(self) -> DomainSet {
        let mut sub_sets: [MaybeUninit<Box<dyn DomainSetSingle>>; DOMAIN_MAX_LENGTH + 1] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for i in 0..=DOMAIN_MAX_LENGTH {
            let mut dummy: Box<dyn DomainSetSingle> = Box::new(FxHashSet::<[u8; 0]>::default());
            std::mem::swap(&mut dummy, &mut self.sub_sets[i].lock().unwrap());
            sub_sets[i] = MaybeUninit::new(dummy);
        }
        DomainSet {
            sub_sets: unsafe { std::mem::transmute::<_, _>(sub_sets) },
        }
    }
}

impl IntoIterator for DomainSetConcurrent {
    type Item = Domain;
    type IntoIter = DomainSetIntoIter;
    fn into_iter(self) -> <Self as IntoIterator>::IntoIter {
        DomainSetIntoIter::new(self.into_single_threaded())
    }
}

#[test]
fn test_empty() {
    let set = DomainSet::default();
    assert_eq!(set.iter().collect::<Vec<_>>(), vec![]);
}

#[test]
fn test_collected_is_original() {
    let mut domains: Vec<_> = ["google.com", "en.m.wikipedia.org", "example.tk"]
        .iter()
        .map(|domain| domain.parse::<Domain>().unwrap())
        .collect();
    domains.sort();
    let mut set = DomainSet::default();
    for domain in domains.iter() {
        set.insert(domain.clone());
    }
    let mut generated = set.iter().collect::<Vec<_>>();
    generated.sort();
    assert_eq!(domains, generated);
}

#[test]
fn test_into_iter_collected_is_original() {
    let mut domains: Vec<_> = ["google.com", "en.m.wikipedia.org", "example.tk"]
        .iter()
        .map(|domain| domain.parse::<Domain>().unwrap())
        .collect();
    domains.sort();
    let mut set = DomainSet::default();
    for domain in domains.iter() {
        set.insert(domain.clone());
    }
    let mut generated = set.into_iter().collect::<Vec<_>>();
    generated.sort();
    assert_eq!(domains, generated);
}

#[test]
fn test_into_iter_is_largest_first() {
    let domains: Vec<_> = ["en.m.wikipedia.org", "www.google.com", "example.tk"]
        .iter()
        .map(|domain| domain.parse::<Domain>().unwrap())
        .collect();
    let mut set = DomainSet::default();
    for domain in domains.iter() {
        set.insert(domain.clone());
    }
    let generated = set.into_iter().collect::<Vec<_>>();
    assert_eq!(domains, generated);
}

#[test]
fn test_collected_concurrent_is_original() {
    let mut domains: Vec<_> = ["google.com", "en.m.wikipedia.org", "example.tk"]
        .iter()
        .map(|domain| domain.parse::<Domain>().unwrap())
        .collect();
    domains.sort();
    let set = DomainSetConcurrent::default();
    for domain in domains.iter() {
        set.insert(domain.clone());
    }
    let mut generated = set.into_iter().collect::<Vec<_>>();
    generated.sort();
    assert_eq!(domains, generated);
}
