AHRE Exam Preparation — By Cesar Ignacio
RENDER VERSION (PARA SA IPHONE AT ANDROID)

Ito ay isang SECURE NODE.JS WEB SERVICE, hindi Static Site. Ang 89 questions at 48 photos ay protected ng login.

PARA I-PUBLISH SA RENDER:
1. Gumawa o mag-login sa GitHub: https://github.com
2. Gumawa ng bagong PRIVATE repository (halimbawa: ahre-exam-cesar).
3. I-upload ANG MGA NILALAMAN ng ZIP sa repository. Dapat nasa pinaka-ugat ng repository ang server.mjs, package.json, render.yaml at public folder. Huwag isama ang sariling password.
4. Sa Render Dashboard https://dashboard.render.com piliin New > Web Service. I-connect ang GitHub at ang repository na ginawa mo.
5. Piliin Free plan kung available, Language = Node. Build Command = npm install. Start Command = npm start.
6. Sa Environment, mag-add ng 3 environment variables:
     LOGIN_USERNAME  = username na ipapamahagi (halimbawa: student)
     LOGIN_PASSWORD  = mahaba at unique na password na ikaw ang pipili; huwag gamitin ang personal login password mo
     SESSION_SECRET  = ibang random secret na 32+ characters. Puwedeng generate ng Render.
7. Piliin Create Web Service / Deploy. Kapag successful, may URL na https://...onrender.com.
8. Buksan ang URL sa Safari sa iPhone, mag-login, pindutin Share > Add to Home Screen > Add.
9. Ibigay nang pribado sa users ang URL at ang shared login.

IMPORTANTE:
- Hindi pa LIVE ang ZIP. Kailangan ma-upload sa GitHub at ma-deploy sa Render.
- Huwag gumamit ng Static Site dahil mae-expose ang bank.js at mga photos kung walang server protection.
- Ang questions ay original practice questions at hindi opisyal na AHRE answer key.
- Ang scores ay nasa browser lang: hindi synchronized sa ibang device.
- Sa Render Free, maaaring matulog ang server kapag walang gumagamit, kaya mabagal ang unang pag-load.
