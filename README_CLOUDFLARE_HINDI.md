# RR DEFENCE ACADEMY BARMER — GitHub → Cloudflare Worker

**केवल ₹199 के 30 CBT मेगा टेस्ट। ऑनलाइन किताब का कोई विकल्प नहीं।**

## अभी का चरण
- मौजूदा GitHub रिपॉजिटरी: `rrdefenceacademy2-create/-rr-defence-academy-barmer`
- मौजूदा Worker: `rr-defence-payment-api`
- GitHub connected; **Disable builds ON ही रखें** जब तक कॉन्फ़िगरेशन पूरी न हो।
- ये पाँचों फाइलें GitHub रिपॉजिटरी के **root** में अपलोड करें। ZIP सीधे अपलोड न करें; GitHub ZIP को अपने-आप unzip नहीं करता।
- `worker.js` में कोई Razorpay Secret या विद्यार्थी की उत्तर-कुंजी नहीं है।

## Deploy से पहले जरूरी
1. Cloudflare D1 `rr-defence-db` का असली database UUID प्राप्त करके `wrangler.toml` में `REPLACE_WITH_REAL_D1_DATABASE_ID` बदलना होगा।
2. `schema.sql` की SQL को Cloudflare D1 Console में चलाना होगा; टेबल की पुष्टि करें।
3. Firebase Project ID व email-verified identity provider कॉन्फ़िगर करें।
4. Secrets को सिर्फ Worker Settings > Variables & Secrets में **Secret** type के रूप में रखें, GitHub में कभी नहीं।
5. भुगतान के Test mode में एक एंड-टू-एंड ऑर्डर, सफल capture, replay/duplicate, पूर्ण refund और access checks सत्यापित करें।
6. Review होने तक `PAYMENTS_ENABLED=false`, `PLAY_PURCHASES_ENABLED=false`, `POLICIES_READY=false`।
7. बाद में Cloudflare Settings > Builds में Disable builds OFF करके Cloudflare Workers Build को trigger किया जाएगा।

**महत्वपूर्ण:** GitHub में ये फाइलें रखने से भुगतान चालू नहीं होता। गलत database ID होने पर deploy fail होना बेहतर है, बनिस्बत बिना डेटाबेस के भुगतान चालू होने के।
