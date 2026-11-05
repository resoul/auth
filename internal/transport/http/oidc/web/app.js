// The sign-in page of the provider. It signs the user in with the browser profile of the /v1 API (an emailed code,
// then a passkey), and hands the access token of that sign-in to /oauth2/login/complete, which answers with where to
// send the browser next. No framework, no storage: the token lives in this closure and the address of this page holds
// only the opaque id of the request.
'use strict';

const translations = {
  en: {
    entryTitle: 'Sign in', entryLead: 'Enter your email. If you don’t have an account yet, we’ll create one.', email: 'Email',
    sendCode: 'Send me a code', signInPasskey: 'Sign in with a passkey',
    codeTitle: 'Enter the code', codeLead: 'We sent an 8-digit code to {email}.', continue: 'Continue',
    resend: 'Send again', resendIn: 'Send again in {seconds} s', changeEmail: 'Use another email',
    createTitle: 'Create a passkey', createLead: 'A passkey replaces a password. It unlocks with Face ID or Touch ID.', createAction: 'Create a passkey',
    useTitle: 'Confirm with your passkey', useLead: 'Your email is confirmed. Use your passkey to finish signing in.', useAction: 'Use my passkey', useLost: 'Lost your passkey?',
    recoveryTitle: 'Enter a recovery code', recoveryLead: 'Use one of the codes you saved. You’ll then create a new passkey: your old ones will be removed and your other devices signed out.', recoveryField: 'Recovery code', back: 'Back',
    replaceTitle: 'Create a new passkey', replaceLead: 'Your old passkeys will stop working as soon as the new one is created.',
    codesTitle: 'Save your recovery codes', codesLead: 'You’ll need one if you lose your passkey. Each works once, and they won’t be shown again.', codesSaved: 'I saved them', codesCopy: 'Copy codes', codesCopied: 'Codes copied',
    errorGeneric: 'That did not work. Try again.', errorEmail: 'That did not work. Check the address.', errorRate: 'Too many tries. Wait a little and try again.',
    errorCode: 'That code was not accepted.', errorPasskeys: 'This browser cannot use passkeys.', errorCancelled: 'The passkey prompt was cancelled.', errorPrompt: 'The passkey prompt failed.',
    errorPasskey: 'That passkey was not accepted. Try another one, or use a recovery code.', errorCreate: 'The passkey was not accepted. Start again.',
    errorRecovery: 'That recovery code was not accepted. Confirm your email again.', errorNoRequest: 'This page was opened without a sign-in request. Start again from the application.', errorExpired: 'The sign-in request expired. Start again from the application.',
  },
  uk: {
    entryTitle: 'Вхід', entryLead: 'Введіть email. Якщо акаунта ще немає, ми його створимо.', email: 'Email',
    sendCode: 'Надіслати код', signInPasskey: 'Увійти за допомогою passkey',
    codeTitle: 'Введіть код', codeLead: 'Ми надіслали 8-значний код на {email}.', continue: 'Продовжити',
    resend: 'Надіслати ще раз', resendIn: 'Надіслати ще раз за {seconds} с', changeEmail: 'Вказати інший email',
    createTitle: 'Створіть passkey', createLead: 'Passkey замінює пароль. Він відкривається через Face ID або Touch ID.', createAction: 'Створити passkey',
    useTitle: 'Підтвердьте за допомогою passkey', useLead: 'Email підтверджено. Використайте passkey, щоб завершити вхід.', useAction: 'Використати passkey', useLost: 'Втратили passkey?',
    recoveryTitle: 'Введіть код відновлення', recoveryLead: 'Використайте один зі збережених кодів. Потім ви створите новий passkey: старі буде видалено, а на інших пристроях виконано вихід.', recoveryField: 'Код відновлення', back: 'Назад',
    replaceTitle: 'Створіть новий passkey', replaceLead: 'Старі passkey перестануть працювати, щойно буде створено новий.',
    codesTitle: 'Збережіть коди відновлення', codesLead: 'Код знадобиться, якщо ви втратите passkey. Кожен діє один раз, і більше їх не покажуть.', codesSaved: 'Я зберіг їх', codesCopy: 'Скопіювати коди', codesCopied: 'Коди скопійовано',
    errorGeneric: 'Не вдалося. Спробуйте ще раз.', errorEmail: 'Не вдалося. Перевірте адресу.', errorRate: 'Забагато спроб. Зачекайте трохи й спробуйте ще раз.',
    errorCode: 'Цей код не прийнято.', errorPasskeys: 'Цей браузер не підтримує passkey.', errorCancelled: 'Запит passkey скасовано.', errorPrompt: 'Не вдалося виконати запит passkey.',
    errorPasskey: 'Цей passkey не прийнято. Спробуйте інший або використайте код відновлення.', errorCreate: 'Passkey не прийнято. Почніть спочатку.',
    errorRecovery: 'Цей код відновлення не прийнято. Підтвердьте email ще раз.', errorNoRequest: 'Сторінку відкрито без запиту на вхід. Почніть спочатку в застосунку.', errorExpired: 'Запит на вхід застарів. Почніть спочатку в застосунку.',
  },
  es: {
    entryTitle: 'Iniciar sesión', entryLead: 'Introduce tu correo. Si aún no tienes cuenta, la crearemos.', email: 'Correo',
    sendCode: 'Enviarme un código', signInPasskey: 'Iniciar sesión con passkey',
    codeTitle: 'Introduce el código', codeLead: 'Enviamos un código de 8 dígitos a {email}.', continue: 'Continuar',
    resend: 'Enviar de nuevo', resendIn: 'Enviar de nuevo en {seconds} s', changeEmail: 'Usar otro correo',
    createTitle: 'Crea una passkey', createLead: 'Una passkey sustituye a la contraseña. Se desbloquea con Face ID o Touch ID.', createAction: 'Crear passkey',
    useTitle: 'Confirma con tu passkey', useLead: 'Tu correo está confirmado. Usa tu passkey para terminar de iniciar sesión.', useAction: 'Usar mi passkey', useLost: '¿Perdiste tu passkey?',
    recoveryTitle: 'Introduce un código de recuperación', recoveryLead: 'Usa uno de los códigos que guardaste. Después crearás una passkey nueva: las anteriores se eliminarán y se cerrará la sesión en tus otros dispositivos.', recoveryField: 'Código de recuperación', back: 'Atrás',
    replaceTitle: 'Crea una passkey nueva', replaceLead: 'Tus passkeys anteriores dejarán de funcionar en cuanto se cree la nueva.',
    codesTitle: 'Guarda tus códigos de recuperación', codesLead: 'Necesitarás uno si pierdes tu passkey. Cada uno funciona una vez y no se volverán a mostrar.', codesSaved: 'Ya los guardé', codesCopy: 'Copiar códigos', codesCopied: 'Códigos copiados',
    errorGeneric: 'No funcionó. Inténtalo de nuevo.', errorEmail: 'No funcionó. Revisa la dirección.', errorRate: 'Demasiados intentos. Espera un poco e inténtalo de nuevo.',
    errorCode: 'Ese código no se aceptó.', errorPasskeys: 'Este navegador no admite passkeys.', errorCancelled: 'Se canceló la solicitud de passkey.', errorPrompt: 'Falló la solicitud de passkey.',
    errorPasskey: 'Esa passkey no se aceptó. Prueba otra o usa un código de recuperación.', errorCreate: 'La passkey no se aceptó. Empieza de nuevo.',
    errorRecovery: 'Ese código de recuperación no se aceptó. Confirma tu correo de nuevo.', errorNoRequest: 'Esta página se abrió sin una solicitud de inicio de sesión. Empieza de nuevo desde la app.', errorExpired: 'La solicitud de inicio de sesión caducó. Empieza de nuevo desde la app.',
  },
  ru: {
    entryTitle: 'Вход', entryLead: 'Введите email. Если аккаунта ещё нет, мы его создадим.', email: 'Email',
    sendCode: 'Отправить код', signInPasskey: 'Войти с помощью passkey',
    codeTitle: 'Введите код', codeLead: 'Мы отправили 8-значный код на {email}.', continue: 'Продолжить',
    resend: 'Отправить ещё раз', resendIn: 'Отправить ещё раз через {seconds} с', changeEmail: 'Указать другой email',
    createTitle: 'Создайте passkey', createLead: 'Passkey заменяет пароль. Он открывается через Face ID или Touch ID.', createAction: 'Создать passkey',
    useTitle: 'Подтвердите с помощью passkey', useLead: 'Email подтверждён. Используйте passkey, чтобы завершить вход.', useAction: 'Использовать passkey', useLost: 'Потеряли passkey?',
    recoveryTitle: 'Введите код восстановления', recoveryLead: 'Используйте один из сохранённых кодов. Затем вы создадите новый passkey: старые будут удалены, а на других устройствах будет выполнен выход.', recoveryField: 'Код восстановления', back: 'Назад',
    replaceTitle: 'Создайте новый passkey', replaceLead: 'Старые passkey перестанут работать, как только будет создан новый.',
    codesTitle: 'Сохраните коды восстановления', codesLead: 'Код понадобится, если вы потеряете passkey. Каждый действует один раз, и больше их не покажут.', codesSaved: 'Коды сохранены', codesCopy: 'Скопировать коды', codesCopied: 'Коды скопированы',
    errorGeneric: 'Не получилось. Попробуйте ещё раз.', errorEmail: 'Не получилось. Проверьте адрес.', errorRate: 'Слишком много попыток. Подождите немного и попробуйте ещё раз.',
    errorCode: 'Этот код не принят.', errorPasskeys: 'Этот браузер не поддерживает passkey.', errorCancelled: 'Запрос passkey отменён.', errorPrompt: 'Не удалось выполнить запрос passkey.',
    errorPasskey: 'Этот passkey не принят. Попробуйте другой или используйте код восстановления.', errorCreate: 'Passkey не принят. Начните сначала.',
    errorRecovery: 'Этот код восстановления не принят. Подтвердите email ещё раз.', errorNoRequest: 'Страница открыта без запроса на вход. Начните сначала в приложении.', errorExpired: 'Запрос на вход устарел. Начните сначала в приложении.',
  },
  it: {
    entryTitle: 'Accedi', entryLead: 'Inserisci la tua email. Se non hai ancora un account, lo creeremo.', email: 'Email',
    sendCode: 'Inviami un codice', signInPasskey: 'Accedi con una passkey',
    codeTitle: 'Inserisci il codice', codeLead: 'Abbiamo inviato un codice di 8 cifre a {email}.', continue: 'Continua',
    resend: 'Invia di nuovo', resendIn: 'Invia di nuovo tra {seconds} s', changeEmail: 'Usa un’altra email',
    createTitle: 'Crea una passkey', createLead: 'Una passkey sostituisce la password. Si sblocca con Face ID o Touch ID.', createAction: 'Crea una passkey',
    useTitle: 'Conferma con la tua passkey', useLead: 'La tua email è confermata. Usa la tua passkey per completare l’accesso.', useAction: 'Usa la mia passkey', useLost: 'Hai perso la passkey?',
    recoveryTitle: 'Inserisci un codice di recupero', recoveryLead: 'Usa uno dei codici che hai salvato. Poi creerai una nuova passkey: quelle vecchie verranno rimosse e gli altri dispositivi verranno disconnessi.', recoveryField: 'Codice di recupero', back: 'Indietro',
    replaceTitle: 'Crea una nuova passkey', replaceLead: 'Le vecchie passkey smetteranno di funzionare non appena verrà creata quella nuova.',
    codesTitle: 'Salva i codici di recupero', codesLead: 'Te ne servirà uno se perdi la passkey. Ognuno funziona una sola volta e non verranno mostrati di nuovo.', codesSaved: 'Li ho salvati', codesCopy: 'Copia i codici', codesCopied: 'Codici copiati',
    errorGeneric: 'Non ha funzionato. Riprova.', errorEmail: 'Non ha funzionato. Controlla l’indirizzo.', errorRate: 'Troppi tentativi. Attendi un po’ e riprova.',
    errorCode: 'Il codice non è stato accettato.', errorPasskeys: 'Questo browser non supporta le passkey.', errorCancelled: 'La richiesta della passkey è stata annullata.', errorPrompt: 'La richiesta della passkey non è riuscita.',
    errorPasskey: 'La passkey non è stata accettata. Provane un’altra o usa un codice di recupero.', errorCreate: 'La passkey non è stata accettata. Ricomincia.',
    errorRecovery: 'Il codice di recupero non è stato accettato. Conferma di nuovo la tua email.', errorNoRequest: 'Questa pagina è stata aperta senza una richiesta di accesso. Ricomincia dall’app.', errorExpired: 'La richiesta di accesso è scaduta. Ricomincia dall’app.',
  },
  ro: {
    entryTitle: 'Conectare', entryLead: 'Introdu adresa de e-mail. Dacă nu ai încă un cont, îl vom crea.', email: 'E-mail',
    sendCode: 'Trimite-mi un cod', signInPasskey: 'Conectează-te cu un passkey',
    codeTitle: 'Introdu codul', codeLead: 'Am trimis un cod de 8 cifre la {email}.', continue: 'Continuă',
    resend: 'Trimite din nou', resendIn: 'Trimite din nou peste {seconds} s', changeEmail: 'Folosește altă adresă',
    createTitle: 'Creează un passkey', createLead: 'Un passkey înlocuiește parola. Se deblochează cu Face ID sau Touch ID.', createAction: 'Creează un passkey',
    useTitle: 'Confirmă cu passkey-ul tău', useLead: 'Adresa ta de e-mail este confirmată. Folosește passkey-ul pentru a finaliza conectarea.', useAction: 'Folosește passkey-ul meu', useLost: 'Ai pierdut passkey-ul?',
    recoveryTitle: 'Introdu un cod de recuperare', recoveryLead: 'Folosește unul dintre codurile salvate. Apoi vei crea un passkey nou: cele vechi vor fi eliminate, iar celelalte dispozitive vor fi deconectate.', recoveryField: 'Cod de recuperare', back: 'Înapoi',
    replaceTitle: 'Creează un passkey nou', replaceLead: 'Passkey-urile vechi nu vor mai funcționa imediat ce este creat cel nou.',
    codesTitle: 'Salvează codurile de recuperare', codesLead: 'Vei avea nevoie de unul dacă pierzi passkey-ul. Fiecare funcționează o singură dată și nu vor mai fi afișate.', codesSaved: 'Le-am salvat', codesCopy: 'Copiază codurile', codesCopied: 'Coduri copiate',
    errorGeneric: 'Nu a funcționat. Încearcă din nou.', errorEmail: 'Nu a funcționat. Verifică adresa.', errorRate: 'Prea multe încercări. Așteaptă puțin și încearcă din nou.',
    errorCode: 'Codul nu a fost acceptat.', errorPasskeys: 'Acest browser nu acceptă passkey-uri.', errorCancelled: 'Solicitarea passkey a fost anulată.', errorPrompt: 'Solicitarea passkey nu a reușit.',
    errorPasskey: 'Passkey-ul nu a fost acceptat. Încearcă altul sau folosește un cod de recuperare.', errorCreate: 'Passkey-ul nu a fost acceptat. Începe din nou.',
    errorRecovery: 'Codul de recuperare nu a fost acceptat. Confirmă din nou adresa de e-mail.', errorNoRequest: 'Această pagină a fost deschisă fără o solicitare de conectare. Începe din nou din aplicație.', errorExpired: 'Solicitarea de conectare a expirat. Începe din nou din aplicație.',
  },
  fr: {
    entryTitle: 'Connexion', entryLead: 'Saisissez votre e-mail. Si vous n’avez pas encore de compte, nous en créerons un.', email: 'E-mail',
    sendCode: 'Recevoir un code', signInPasskey: 'Se connecter avec une passkey',
    codeTitle: 'Saisissez le code', codeLead: 'Nous avons envoyé un code à 8 chiffres à {email}.', continue: 'Continuer',
    resend: 'Renvoyer', resendIn: 'Renvoyer dans {seconds} s', changeEmail: 'Utiliser un autre e-mail',
    createTitle: 'Créez une passkey', createLead: 'Une passkey remplace le mot de passe. Elle se déverrouille avec Face ID ou Touch ID.', createAction: 'Créer une passkey',
    useTitle: 'Confirmez avec votre passkey', useLead: 'Votre e-mail est confirmé. Utilisez votre passkey pour terminer la connexion.', useAction: 'Utiliser ma passkey', useLost: 'Passkey perdue ?',
    recoveryTitle: 'Saisissez un code de récupération', recoveryLead: 'Utilisez l’un des codes que vous avez enregistrés. Vous créerez ensuite une nouvelle passkey : les anciennes seront supprimées et vos autres appareils déconnectés.', recoveryField: 'Code de récupération', back: 'Retour',
    replaceTitle: 'Créez une nouvelle passkey', replaceLead: 'Vos anciennes passkeys cesseront de fonctionner dès que la nouvelle sera créée.',
    codesTitle: 'Enregistrez vos codes de récupération', codesLead: 'Vous en aurez besoin si vous perdez votre passkey. Chaque code ne fonctionne qu’une fois et ils ne seront plus affichés.', codesSaved: 'Je les ai enregistrés', codesCopy: 'Copier les codes', codesCopied: 'Codes copiés',
    errorGeneric: 'Cela n’a pas fonctionné. Réessayez.', errorEmail: 'Cela n’a pas fonctionné. Vérifiez l’adresse.', errorRate: 'Trop de tentatives. Patientez un peu et réessayez.',
    errorCode: 'Ce code n’a pas été accepté.', errorPasskeys: 'Ce navigateur ne prend pas en charge les passkeys.', errorCancelled: 'La demande de passkey a été annulée.', errorPrompt: 'La demande de passkey a échoué.',
    errorPasskey: 'Cette passkey n’a pas été acceptée. Essayez-en une autre ou utilisez un code de récupération.', errorCreate: 'La passkey n’a pas été acceptée. Recommencez.',
    errorRecovery: 'Ce code de récupération n’a pas été accepté. Confirmez de nouveau votre e-mail.', errorNoRequest: 'Cette page a été ouverte sans demande de connexion. Recommencez depuis l’application.', errorExpired: 'La demande de connexion a expiré. Recommencez depuis l’application.',
  },
  de: {
    entryTitle: 'Anmelden', entryLead: 'Gib deine E-Mail-Adresse ein. Wenn du noch kein Konto hast, erstellen wir eins.', email: 'E-Mail',
    sendCode: 'Code senden', signInPasskey: 'Mit Passkey anmelden',
    codeTitle: 'Code eingeben', codeLead: 'Wir haben einen 8-stelligen Code an {email} gesendet.', continue: 'Weiter',
    resend: 'Erneut senden', resendIn: 'Erneut senden in {seconds} s', changeEmail: 'Andere E-Mail-Adresse verwenden',
    createTitle: 'Passkey erstellen', createLead: 'Ein Passkey ersetzt das Passwort. Er wird mit Face ID oder Touch ID entsperrt.', createAction: 'Passkey erstellen',
    useTitle: 'Mit deinem Passkey bestätigen', useLead: 'Deine E-Mail-Adresse ist bestätigt. Verwende deinen Passkey, um die Anmeldung abzuschließen.', useAction: 'Meinen Passkey verwenden', useLost: 'Passkey verloren?',
    recoveryTitle: 'Wiederherstellungscode eingeben', recoveryLead: 'Verwende einen deiner gespeicherten Codes. Danach erstellst du einen neuen Passkey: Die alten werden entfernt und deine anderen Geräte abgemeldet.', recoveryField: 'Wiederherstellungscode', back: 'Zurück',
    replaceTitle: 'Neuen Passkey erstellen', replaceLead: 'Deine alten Passkeys funktionieren nicht mehr, sobald der neue erstellt ist.',
    codesTitle: 'Wiederherstellungscodes speichern', codesLead: 'Du brauchst einen davon, wenn du deinen Passkey verlierst. Jeder funktioniert nur einmal, und sie werden nicht noch einmal angezeigt.', codesSaved: 'Ich habe sie gespeichert', codesCopy: 'Codes kopieren', codesCopied: 'Codes kopiert',
    errorGeneric: 'Das hat nicht geklappt. Versuche es erneut.', errorEmail: 'Das hat nicht geklappt. Prüfe die Adresse.', errorRate: 'Zu viele Versuche. Warte kurz und versuche es erneut.',
    errorCode: 'Dieser Code wurde nicht akzeptiert.', errorPasskeys: 'Dieser Browser unterstützt keine Passkeys.', errorCancelled: 'Die Passkey-Abfrage wurde abgebrochen.', errorPrompt: 'Die Passkey-Abfrage ist fehlgeschlagen.',
    errorPasskey: 'Dieser Passkey wurde nicht akzeptiert. Versuche einen anderen oder verwende einen Wiederherstellungscode.', errorCreate: 'Der Passkey wurde nicht akzeptiert. Beginne von vorn.',
    errorRecovery: 'Dieser Wiederherstellungscode wurde nicht akzeptiert. Bestätige deine E-Mail-Adresse erneut.', errorNoRequest: 'Diese Seite wurde ohne Anmeldeanfrage geöffnet. Beginne erneut in der App.', errorExpired: 'Die Anmeldeanfrage ist abgelaufen. Beginne erneut in der App.',
  },
};

const language = (navigator.languages || [navigator.language]).map((tag) => String(tag).slice(0, 2).toLowerCase()).find((tag) => translations[tag]) || 'en';
const t = (key, values = {}) => (translations[language][key] || '').replace(/\{(\w+)\}/g, (_, name) => values[name]);

const $ = (id) => document.getElementById(id);
const steps = ['choose', 'codeStep', 'createStep', 'useStep', 'recoveryStep', 'replaceStep', 'codesStep'];
const resendDelay = 60;
const requestID = new URLSearchParams(location.search).get('request');
let flowID = null; // the emailed-code flow
let ticket = null; // what the server issued once the email was proven
let pending = null; // an access token waiting for the user to save their recovery codes
let resendTimer = null;

document.documentElement.lang = language;
for (const element of document.querySelectorAll('[data-t]')) element.textContent = t(element.dataset.t);
for (const element of document.querySelectorAll('[data-p]')) element.placeholder = t(element.dataset.p);

function say(text) { $('message').textContent = text || ''; }
function show(id) {
  say('');
  for (const step of steps) $(step).hidden = step !== id;
  const field = $(id).querySelector('input');
  if (field) field.focus();
}

async function call(method, path, { body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: response.status, json };
}

// busy keeps a button from being pressed twice while its request runs, and turns a lost network into a message.
function busy(button, action) {
  return async (event) => {
    if (event) event.preventDefault();
    button.disabled = true;
    try {
      await action();
    } catch {
      say(t('errorGeneric'));
    } finally {
      button.disabled = false;
    }
  };
}

// --- WebAuthn plumbing: the JSON forms where the browser has them, a small conversion where it does not ------------

const toBytes = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)).buffer;
const toText = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function creationOptions(options) {
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return { publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey) };
  const key = { ...options.publicKey, challenge: toBytes(options.publicKey.challenge) };
  key.user = { ...key.user, id: toBytes(key.user.id) };
  key.excludeCredentials = (key.excludeCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) }));
  return { publicKey: key };
}

function requestOptions(options) {
  if (PublicKeyCredential.parseRequestOptionsFromJSON) return { publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey) };
  const key = { ...options.publicKey, challenge: toBytes(options.publicKey.challenge) };
  key.allowCredentials = (key.allowCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) }));
  return { publicKey: key };
}

function credentialJSON(credential) {
  if (credential.toJSON) return credential.toJSON();
  const r = credential.response;
  const response = { clientDataJSON: toText(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = toText(r.attestationObject);
    response.transports = r.getTransports ? r.getTransports() : [];
  } else {
    response.authenticatorData = toText(r.authenticatorData);
    response.signature = toText(r.signature);
    if (r.userHandle) response.userHandle = toText(r.userHandle);
  }
  return { id: credential.id, rawId: toText(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults() };
}

// ceremony runs a begin route and the browser's own prompt; it returns what the finish route needs, or null.
async function ceremony(beginPath, body, run) {
  if (!window.PublicKeyCredential) { say(t('errorPasskeys')); return null; }
  const begun = await call('POST', beginPath, { body });
  if (begun.status !== 200) { say(t('errorGeneric')); return null; }
  try {
    const credential = await run(begun.json.options);
    return { challenge_id: begun.json.challenge_id, credential: credentialJSON(credential) };
  } catch (error) {
    say(error.name === 'NotAllowedError' ? t('errorCancelled') : t('errorPrompt'));
    return null;
  }
}

// --- finishing -------------------------------------------------------------------------------------------------------

async function complete(token) {
  if (!requestID) { say(t('errorNoRequest')); return; }
  const done = await call('POST', '/oauth2/login/complete', { token, body: { request_id: requestID } });
  if (done.status === 200 && done.json && done.json.redirect_to) {
    location.replace(done.json.redirect_to);
    return;
  }
  say(t('errorExpired'));
}

function startResendCountdown() {
  clearInterval(resendTimer);
  let left = resendDelay;
  const button = $('resend');
  const paint = () => {
    button.disabled = left > 0;
    button.textContent = left > 0 ? t('resendIn', { seconds: left }) : t('resend');
  };
  paint();
  resendTimer = setInterval(() => {
    left -= 1;
    paint();
    if (left <= 0) clearInterval(resendTimer);
  }, 1000);
}

function showNext(next, nextTicket) {
  ticket = nextTicket;
  show(next === 'enroll_passkey' ? 'createStep' : 'useStep');
}

// --- actions ---------------------------------------------------------------------------------------------------------

async function usePasskey(withTicket) {
  say('');
  const done = await ceremony('/v1/auth/passkey/login/options', undefined, (options) => navigator.credentials.get(requestOptions(options)));
  if (!done) return;
  const response = await call('POST', '/v1/auth/passkey/login/verify', { body: { ...done, ...(withTicket ? { ticket: withTicket } : {}), device_name: 'browser' } });
  if (response.status !== 200) { say(t('errorPasskey')); return; }
  await complete(response.json.access_token);
}

async function createPasskey() {
  say('');
  const done = await ceremony('/v1/auth/passkey/register/options', { ticket }, (options) => navigator.credentials.create(creationOptions(options)));
  if (!done) return;
  const response = await call('POST', '/v1/auth/passkey/register/verify', { body: { ticket, ...done, name: 'passkey', device_name: 'browser' } });
  if (response.status !== 200) { say(t('errorCreate')); return; }
  // A new account gets recovery codes. They are shown once, so the user is asked to save them before going on.
  if (response.json.recovery_codes && response.json.recovery_codes.length) {
    pending = response.json.access_token;
    $('codeList').textContent = response.json.recovery_codes.join('\n');
    show('codesStep');
  } else {
    await complete(response.json.access_token);
  }
}

$('passkey').onclick = busy($('passkey'), () => usePasskey(null));
$('usePasskey').onclick = busy($('usePasskey'), () => usePasskey(ticket));
$('createPasskey').onclick = busy($('createPasskey'), createPasskey);
$('replacePasskey').onclick = busy($('replacePasskey'), createPasskey);
$('lostPasskey').onclick = () => show('recoveryStep');
$('recoveryBack').onclick = () => show('useStep');
$('changeEmail').onclick = () => { clearInterval(resendTimer); flowID = null; show('choose'); };

$('emailForm').onsubmit = busy($('emailForm').querySelector('button'), async () => {
  say('');
  const email = $('email').value.trim();
  const response = await call('POST', '/v1/auth/email/start', { body: { email } });
  if (response.status !== 202) { say(response.status === 429 ? t('errorRate') : t('errorEmail')); return; }
  flowID = response.json.flow_id;
  $('code').value = '';
  $('codeLead').textContent = t('codeLead', { email });
  show('codeStep');
  startResendCountdown();
});

$('code').oninput = () => {
  const digits = $('code').value.replace(/\D/g, '').slice(0, 8);
  $('code').value = digits.length > 4 ? `${digits.slice(0, 4)} ${digits.slice(4)}` : digits;
};

$('codeForm').onsubmit = busy($('codeForm').querySelector('button'), async () => {
  say('');
  const code = $('code').value.replace(/\s+/g, '');
  const response = await call('POST', '/v1/auth/email/verify', { body: { flow_id: flowID, code } });
  $('code').value = '';
  if (response.status !== 200) { say(t('errorCode')); return; }
  flowID = null;
  clearInterval(resendTimer);
  showNext(response.json.next, response.json.ticket);
});

$('resend').onclick = async () => {
  say('');
  startResendCountdown();
  try {
    const response = await call('POST', '/v1/auth/email/resend', { body: { flow_id: flowID } });
    if (response.status !== 202) say(response.status === 429 ? t('errorRate') : t('errorGeneric'));
  } catch {
    say(t('errorGeneric'));
  }
};

$('recoveryForm').onsubmit = busy($('recoveryForm').querySelector('button'), async () => {
  say('');
  const response = await call('POST', '/v1/auth/recovery/verify', { body: { ticket, code: $('recovery').value.trim() } });
  $('recovery').value = '';
  if (response.status !== 200) { ticket = null; show('choose'); say(t('errorRecovery')); return; }
  ticket = response.json.ticket;
  show('replaceStep');
});

$('codesSaved').onclick = busy($('codesSaved'), async () => {
  $('codeList').textContent = '';
  const token = pending;
  pending = null;
  await complete(token);
});

$('codesCopy').onclick = async () => {
  try {
    await navigator.clipboard.writeText($('codeList').textContent);
    say('');
    $('codesCopy').textContent = t('codesCopied');
  } catch {
    say(t('errorGeneric'));
  }
};

show('choose');
