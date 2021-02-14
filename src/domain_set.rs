use std::collections::HashSet;

use crate::Domain;

trait DomainSetSingle {
    fn wrapper_contains(&self, domain: &[u8]) -> bool;
    fn wrapper_insert(&mut self, domain: &[u8]) -> bool;
    fn wrapper_remove(&mut self, domain: &[u8]) -> bool;
    fn wrapper_into_iter(self: Box<Self>) -> Box<dyn Iterator<Item = Domain>>;
    fn wrapper_iter(&self) -> Box<dyn Iterator<Item = Domain> + '_>;
    fn wrapper_drain(&mut self) -> Box<dyn Iterator<Item = Domain> + '_>;
    fn wrapper_shrink_to_fit(&mut self);
    fn wrapper_len(&self) -> usize;
    fn wrapper_is_empty(&self) -> bool;
}

macro_rules! implement_domain_set_single {
    ($n: expr) => {
        impl DomainSetSingle for HashSet<[u8; $n]> {
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
            fn wrapper_drain(&mut self) -> Box<dyn Iterator<Item = Domain> + '_> {
                Box::new(self.drain().flat_map(|domain| {
                    std::str::from_utf8(&domain)
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
            let mut dummy: Box<dyn DomainSetSingle> = Box::new(HashSet::<[u8; 0]>::new());
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
            current_iterator.next()
        } else {
            if let Some(next_iterator) = self.sub_sets.pop() {
                let next_iterator = next_iterator.wrapper_into_iter();
                let mut next_iterator = Some(next_iterator);
                std::mem::swap(&mut next_iterator, &mut self.current_iterator);
                if self.sub_sets.is_empty() {
                    self.sub_sets.shrink_to_fit();
                }
            }
            self.next()
        }
    }
}

pub struct DomainSet {
    sub_sets: [Box<dyn DomainSetSingle>; 254],
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
                Box::new(HashSet::<[u8; 0]>::new()),
                Box::new(HashSet::<[u8; 1]>::new()),
                Box::new(HashSet::<[u8; 2]>::new()),
                Box::new(HashSet::<[u8; 3]>::new()),
                Box::new(HashSet::<[u8; 4]>::new()),
                Box::new(HashSet::<[u8; 5]>::new()),
                Box::new(HashSet::<[u8; 6]>::new()),
                Box::new(HashSet::<[u8; 7]>::new()),
                Box::new(HashSet::<[u8; 8]>::new()),
                Box::new(HashSet::<[u8; 9]>::new()),
                Box::new(HashSet::<[u8; 10]>::new()),
                Box::new(HashSet::<[u8; 11]>::new()),
                Box::new(HashSet::<[u8; 12]>::new()),
                Box::new(HashSet::<[u8; 13]>::new()),
                Box::new(HashSet::<[u8; 14]>::new()),
                Box::new(HashSet::<[u8; 15]>::new()),
                Box::new(HashSet::<[u8; 16]>::new()),
                Box::new(HashSet::<[u8; 17]>::new()),
                Box::new(HashSet::<[u8; 18]>::new()),
                Box::new(HashSet::<[u8; 19]>::new()),
                Box::new(HashSet::<[u8; 20]>::new()),
                Box::new(HashSet::<[u8; 21]>::new()),
                Box::new(HashSet::<[u8; 22]>::new()),
                Box::new(HashSet::<[u8; 23]>::new()),
                Box::new(HashSet::<[u8; 24]>::new()),
                Box::new(HashSet::<[u8; 25]>::new()),
                Box::new(HashSet::<[u8; 26]>::new()),
                Box::new(HashSet::<[u8; 27]>::new()),
                Box::new(HashSet::<[u8; 28]>::new()),
                Box::new(HashSet::<[u8; 29]>::new()),
                Box::new(HashSet::<[u8; 30]>::new()),
                Box::new(HashSet::<[u8; 31]>::new()),
                Box::new(HashSet::<[u8; 32]>::new()),
                Box::new(HashSet::<[u8; 33]>::new()),
                Box::new(HashSet::<[u8; 34]>::new()),
                Box::new(HashSet::<[u8; 35]>::new()),
                Box::new(HashSet::<[u8; 36]>::new()),
                Box::new(HashSet::<[u8; 37]>::new()),
                Box::new(HashSet::<[u8; 38]>::new()),
                Box::new(HashSet::<[u8; 39]>::new()),
                Box::new(HashSet::<[u8; 40]>::new()),
                Box::new(HashSet::<[u8; 41]>::new()),
                Box::new(HashSet::<[u8; 42]>::new()),
                Box::new(HashSet::<[u8; 43]>::new()),
                Box::new(HashSet::<[u8; 44]>::new()),
                Box::new(HashSet::<[u8; 45]>::new()),
                Box::new(HashSet::<[u8; 46]>::new()),
                Box::new(HashSet::<[u8; 47]>::new()),
                Box::new(HashSet::<[u8; 48]>::new()),
                Box::new(HashSet::<[u8; 49]>::new()),
                Box::new(HashSet::<[u8; 50]>::new()),
                Box::new(HashSet::<[u8; 51]>::new()),
                Box::new(HashSet::<[u8; 52]>::new()),
                Box::new(HashSet::<[u8; 53]>::new()),
                Box::new(HashSet::<[u8; 54]>::new()),
                Box::new(HashSet::<[u8; 55]>::new()),
                Box::new(HashSet::<[u8; 56]>::new()),
                Box::new(HashSet::<[u8; 57]>::new()),
                Box::new(HashSet::<[u8; 58]>::new()),
                Box::new(HashSet::<[u8; 59]>::new()),
                Box::new(HashSet::<[u8; 60]>::new()),
                Box::new(HashSet::<[u8; 61]>::new()),
                Box::new(HashSet::<[u8; 62]>::new()),
                Box::new(HashSet::<[u8; 63]>::new()),
                Box::new(HashSet::<[u8; 64]>::new()),
                Box::new(HashSet::<[u8; 65]>::new()),
                Box::new(HashSet::<[u8; 66]>::new()),
                Box::new(HashSet::<[u8; 67]>::new()),
                Box::new(HashSet::<[u8; 68]>::new()),
                Box::new(HashSet::<[u8; 69]>::new()),
                Box::new(HashSet::<[u8; 70]>::new()),
                Box::new(HashSet::<[u8; 71]>::new()),
                Box::new(HashSet::<[u8; 72]>::new()),
                Box::new(HashSet::<[u8; 73]>::new()),
                Box::new(HashSet::<[u8; 74]>::new()),
                Box::new(HashSet::<[u8; 75]>::new()),
                Box::new(HashSet::<[u8; 76]>::new()),
                Box::new(HashSet::<[u8; 77]>::new()),
                Box::new(HashSet::<[u8; 78]>::new()),
                Box::new(HashSet::<[u8; 79]>::new()),
                Box::new(HashSet::<[u8; 80]>::new()),
                Box::new(HashSet::<[u8; 81]>::new()),
                Box::new(HashSet::<[u8; 82]>::new()),
                Box::new(HashSet::<[u8; 83]>::new()),
                Box::new(HashSet::<[u8; 84]>::new()),
                Box::new(HashSet::<[u8; 85]>::new()),
                Box::new(HashSet::<[u8; 86]>::new()),
                Box::new(HashSet::<[u8; 87]>::new()),
                Box::new(HashSet::<[u8; 88]>::new()),
                Box::new(HashSet::<[u8; 89]>::new()),
                Box::new(HashSet::<[u8; 90]>::new()),
                Box::new(HashSet::<[u8; 91]>::new()),
                Box::new(HashSet::<[u8; 92]>::new()),
                Box::new(HashSet::<[u8; 93]>::new()),
                Box::new(HashSet::<[u8; 94]>::new()),
                Box::new(HashSet::<[u8; 95]>::new()),
                Box::new(HashSet::<[u8; 96]>::new()),
                Box::new(HashSet::<[u8; 97]>::new()),
                Box::new(HashSet::<[u8; 98]>::new()),
                Box::new(HashSet::<[u8; 99]>::new()),
                Box::new(HashSet::<[u8; 100]>::new()),
                Box::new(HashSet::<[u8; 101]>::new()),
                Box::new(HashSet::<[u8; 102]>::new()),
                Box::new(HashSet::<[u8; 103]>::new()),
                Box::new(HashSet::<[u8; 104]>::new()),
                Box::new(HashSet::<[u8; 105]>::new()),
                Box::new(HashSet::<[u8; 106]>::new()),
                Box::new(HashSet::<[u8; 107]>::new()),
                Box::new(HashSet::<[u8; 108]>::new()),
                Box::new(HashSet::<[u8; 109]>::new()),
                Box::new(HashSet::<[u8; 110]>::new()),
                Box::new(HashSet::<[u8; 111]>::new()),
                Box::new(HashSet::<[u8; 112]>::new()),
                Box::new(HashSet::<[u8; 113]>::new()),
                Box::new(HashSet::<[u8; 114]>::new()),
                Box::new(HashSet::<[u8; 115]>::new()),
                Box::new(HashSet::<[u8; 116]>::new()),
                Box::new(HashSet::<[u8; 117]>::new()),
                Box::new(HashSet::<[u8; 118]>::new()),
                Box::new(HashSet::<[u8; 119]>::new()),
                Box::new(HashSet::<[u8; 120]>::new()),
                Box::new(HashSet::<[u8; 121]>::new()),
                Box::new(HashSet::<[u8; 122]>::new()),
                Box::new(HashSet::<[u8; 123]>::new()),
                Box::new(HashSet::<[u8; 124]>::new()),
                Box::new(HashSet::<[u8; 125]>::new()),
                Box::new(HashSet::<[u8; 126]>::new()),
                Box::new(HashSet::<[u8; 127]>::new()),
                Box::new(HashSet::<[u8; 128]>::new()),
                Box::new(HashSet::<[u8; 129]>::new()),
                Box::new(HashSet::<[u8; 130]>::new()),
                Box::new(HashSet::<[u8; 131]>::new()),
                Box::new(HashSet::<[u8; 132]>::new()),
                Box::new(HashSet::<[u8; 133]>::new()),
                Box::new(HashSet::<[u8; 134]>::new()),
                Box::new(HashSet::<[u8; 135]>::new()),
                Box::new(HashSet::<[u8; 136]>::new()),
                Box::new(HashSet::<[u8; 137]>::new()),
                Box::new(HashSet::<[u8; 138]>::new()),
                Box::new(HashSet::<[u8; 139]>::new()),
                Box::new(HashSet::<[u8; 140]>::new()),
                Box::new(HashSet::<[u8; 141]>::new()),
                Box::new(HashSet::<[u8; 142]>::new()),
                Box::new(HashSet::<[u8; 143]>::new()),
                Box::new(HashSet::<[u8; 144]>::new()),
                Box::new(HashSet::<[u8; 145]>::new()),
                Box::new(HashSet::<[u8; 146]>::new()),
                Box::new(HashSet::<[u8; 147]>::new()),
                Box::new(HashSet::<[u8; 148]>::new()),
                Box::new(HashSet::<[u8; 149]>::new()),
                Box::new(HashSet::<[u8; 150]>::new()),
                Box::new(HashSet::<[u8; 151]>::new()),
                Box::new(HashSet::<[u8; 152]>::new()),
                Box::new(HashSet::<[u8; 153]>::new()),
                Box::new(HashSet::<[u8; 154]>::new()),
                Box::new(HashSet::<[u8; 155]>::new()),
                Box::new(HashSet::<[u8; 156]>::new()),
                Box::new(HashSet::<[u8; 157]>::new()),
                Box::new(HashSet::<[u8; 158]>::new()),
                Box::new(HashSet::<[u8; 159]>::new()),
                Box::new(HashSet::<[u8; 160]>::new()),
                Box::new(HashSet::<[u8; 161]>::new()),
                Box::new(HashSet::<[u8; 162]>::new()),
                Box::new(HashSet::<[u8; 163]>::new()),
                Box::new(HashSet::<[u8; 164]>::new()),
                Box::new(HashSet::<[u8; 165]>::new()),
                Box::new(HashSet::<[u8; 166]>::new()),
                Box::new(HashSet::<[u8; 167]>::new()),
                Box::new(HashSet::<[u8; 168]>::new()),
                Box::new(HashSet::<[u8; 169]>::new()),
                Box::new(HashSet::<[u8; 170]>::new()),
                Box::new(HashSet::<[u8; 171]>::new()),
                Box::new(HashSet::<[u8; 172]>::new()),
                Box::new(HashSet::<[u8; 173]>::new()),
                Box::new(HashSet::<[u8; 174]>::new()),
                Box::new(HashSet::<[u8; 175]>::new()),
                Box::new(HashSet::<[u8; 176]>::new()),
                Box::new(HashSet::<[u8; 177]>::new()),
                Box::new(HashSet::<[u8; 178]>::new()),
                Box::new(HashSet::<[u8; 179]>::new()),
                Box::new(HashSet::<[u8; 180]>::new()),
                Box::new(HashSet::<[u8; 181]>::new()),
                Box::new(HashSet::<[u8; 182]>::new()),
                Box::new(HashSet::<[u8; 183]>::new()),
                Box::new(HashSet::<[u8; 184]>::new()),
                Box::new(HashSet::<[u8; 185]>::new()),
                Box::new(HashSet::<[u8; 186]>::new()),
                Box::new(HashSet::<[u8; 187]>::new()),
                Box::new(HashSet::<[u8; 188]>::new()),
                Box::new(HashSet::<[u8; 189]>::new()),
                Box::new(HashSet::<[u8; 190]>::new()),
                Box::new(HashSet::<[u8; 191]>::new()),
                Box::new(HashSet::<[u8; 192]>::new()),
                Box::new(HashSet::<[u8; 193]>::new()),
                Box::new(HashSet::<[u8; 194]>::new()),
                Box::new(HashSet::<[u8; 195]>::new()),
                Box::new(HashSet::<[u8; 196]>::new()),
                Box::new(HashSet::<[u8; 197]>::new()),
                Box::new(HashSet::<[u8; 198]>::new()),
                Box::new(HashSet::<[u8; 199]>::new()),
                Box::new(HashSet::<[u8; 200]>::new()),
                Box::new(HashSet::<[u8; 201]>::new()),
                Box::new(HashSet::<[u8; 202]>::new()),
                Box::new(HashSet::<[u8; 203]>::new()),
                Box::new(HashSet::<[u8; 204]>::new()),
                Box::new(HashSet::<[u8; 205]>::new()),
                Box::new(HashSet::<[u8; 206]>::new()),
                Box::new(HashSet::<[u8; 207]>::new()),
                Box::new(HashSet::<[u8; 208]>::new()),
                Box::new(HashSet::<[u8; 209]>::new()),
                Box::new(HashSet::<[u8; 210]>::new()),
                Box::new(HashSet::<[u8; 211]>::new()),
                Box::new(HashSet::<[u8; 212]>::new()),
                Box::new(HashSet::<[u8; 213]>::new()),
                Box::new(HashSet::<[u8; 214]>::new()),
                Box::new(HashSet::<[u8; 215]>::new()),
                Box::new(HashSet::<[u8; 216]>::new()),
                Box::new(HashSet::<[u8; 217]>::new()),
                Box::new(HashSet::<[u8; 218]>::new()),
                Box::new(HashSet::<[u8; 219]>::new()),
                Box::new(HashSet::<[u8; 220]>::new()),
                Box::new(HashSet::<[u8; 221]>::new()),
                Box::new(HashSet::<[u8; 222]>::new()),
                Box::new(HashSet::<[u8; 223]>::new()),
                Box::new(HashSet::<[u8; 224]>::new()),
                Box::new(HashSet::<[u8; 225]>::new()),
                Box::new(HashSet::<[u8; 226]>::new()),
                Box::new(HashSet::<[u8; 227]>::new()),
                Box::new(HashSet::<[u8; 228]>::new()),
                Box::new(HashSet::<[u8; 229]>::new()),
                Box::new(HashSet::<[u8; 230]>::new()),
                Box::new(HashSet::<[u8; 231]>::new()),
                Box::new(HashSet::<[u8; 232]>::new()),
                Box::new(HashSet::<[u8; 233]>::new()),
                Box::new(HashSet::<[u8; 234]>::new()),
                Box::new(HashSet::<[u8; 235]>::new()),
                Box::new(HashSet::<[u8; 236]>::new()),
                Box::new(HashSet::<[u8; 237]>::new()),
                Box::new(HashSet::<[u8; 238]>::new()),
                Box::new(HashSet::<[u8; 239]>::new()),
                Box::new(HashSet::<[u8; 240]>::new()),
                Box::new(HashSet::<[u8; 241]>::new()),
                Box::new(HashSet::<[u8; 242]>::new()),
                Box::new(HashSet::<[u8; 243]>::new()),
                Box::new(HashSet::<[u8; 244]>::new()),
                Box::new(HashSet::<[u8; 245]>::new()),
                Box::new(HashSet::<[u8; 246]>::new()),
                Box::new(HashSet::<[u8; 247]>::new()),
                Box::new(HashSet::<[u8; 248]>::new()),
                Box::new(HashSet::<[u8; 249]>::new()),
                Box::new(HashSet::<[u8; 250]>::new()),
                Box::new(HashSet::<[u8; 251]>::new()),
                Box::new(HashSet::<[u8; 252]>::new()),
                Box::new(HashSet::<[u8; 253]>::new()),
            ],
        }
    }

    pub fn contains(&self, domain: &Domain) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()].wrapper_contains(&domain_bytes)
    }
    pub fn insert(&mut self, domain: Domain) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()].wrapper_insert(&domain_bytes)
    }
    pub fn remove(&mut self, domain: &Domain) -> bool {
        let domain_bytes = domain.as_bytes();
        self.sub_sets[domain_bytes.len()].wrapper_remove(&domain_bytes)
    }
    pub fn iter(&self) -> impl Iterator<Item = Domain> + '_ {
        self.sub_sets.iter().flat_map(|sub_set| sub_set.wrapper_iter())
    }
    pub fn drain(&mut self) -> impl Iterator<Item = Domain> + '_ {
        self.sub_sets
            .iter_mut()
            .rev()
            .flat_map(|sub_set| sub_set.wrapper_drain())
    }
    pub fn shrink_to_fit(&mut self) {
        for sub_set in self.sub_sets.iter_mut() {
            sub_set.wrapper_shrink_to_fit();
        }
    }
    pub fn len(&self) -> usize {
        self.sub_sets.iter().map(|sub_set| sub_set.wrapper_len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.sub_sets.iter().all(|sub_set| sub_set.wrapper_is_empty())
    }
}

impl IntoIterator for DomainSet {
    type Item = Domain;
    type IntoIter = DomainSetIntoIter;
    fn into_iter(self) -> <Self as IntoIterator>::IntoIter {
        DomainSetIntoIter::new(self)
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
    generated.sort();
    assert_eq!(domains, generated);
}

#[test]
fn test_multiple_domain_sets() {
    let mut domains: Vec<_> = ["google.com", "en.m.wikipedia.org", "example.tk"]
        .iter()
        .map(|domain| domain.parse::<Domain>().unwrap())
        .collect();
    domains.sort();
    let mut sets = Vec::new();
    for _ in 0..1000 {
        sets.push(DomainSet::default());
    }
    for domain in domains.iter() {
        for set in sets.iter_mut() {
            set.insert(domain.clone());
        }
    }
    for set in sets.iter() {
        let mut generated = set.iter().collect::<Vec<_>>();
        generated.sort();
        generated.sort();
        assert_eq!(domains, generated);
    }
}
