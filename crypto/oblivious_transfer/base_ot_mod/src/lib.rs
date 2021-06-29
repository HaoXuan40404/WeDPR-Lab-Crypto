#[macro_use]
extern crate lazy_static;

pub mod constant;
pub mod utils;

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn it_works() {
        let prime_mod = BigUint::from_str("22066536338414323739865000721479941688019446300001727050033863123404508527360057382124431592487175552430214339019932977294438440994766853956747138992782925456829948399227941849596640104139709789897368750691388960480472054706025487529749292052027891171033028716913786485193581436348261797311173683194607566365759850535255366649852649228282281522574257602608653522735179675714896962913724066743735611355498831010057144313259386573625020235737194132968653752006026401256180969976174021974937728920791787186442242767314122749675344165399072583396362702154987714935195101739518213021236819473535057784900656398711233040427").unwrap();
        let prime_gen = BigUint::from_str("21967776453576425418401845975004568131328756948517171056887978357803037829568879921671582562682834869268458693220178940296762093275708539056500850220701423436253549516692322294566575394724161597988209569075339356219938032314547111217962796852472235866809694733568073434189840033571185928562157743032806061986802973509384288857210981073943845944525063097134620867285393169672223797738231250393852177901783342394915102874707020281747941442896665787806091821561888468560319383163287935077324049516667817847046679134650369734057189968145858211980242981359451590399925956110049309589712838467090785843798902998395786695163").unwrap();
        println!("prime_mod = {:?}", prime_mod);
        println!("prime_gen = {:?}", prime_gen);
        let random_biguint = utils::get_random_biguint();
        println!("random_biguint = {:?}", random_biguint);


    }
}
