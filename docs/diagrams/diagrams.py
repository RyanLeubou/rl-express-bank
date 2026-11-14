from gen import *
pages=[]

# 1 Architecture
pages.append(flow('1. Architecture', 'TB', {
 'SPA':('SPA React / TypeScript\nClient · Admin · SOC · Auditeur · Support','box'),
 'CHAT':('Widget RL SOLUTION','ai'),
 'ATM':('Kiosque ATM simulé\n/atm/:atmId','box'),
 'PROXY':('Caddy\nTLS local · en-têtes sécurité','grey'),
 'API':('API FastAPI /api/v1\nAuth · RBAC · Banque · ATM\nRisk · Policy · Step-up · Support','box'),
 'WORKER':('Worker Python\noutbox · corrélation · profils · IA','box'),
 'DB':('PostgreSQL','db'),
 'KV':('Valkey\nrate limiting · challenges','db'),
 'LOGS':('rlbank-events.jsonl','file'),
 'MAIL':('Mailpit\ne-mails simulés','grey'),
 'LLM':('Groq (Internet, HTTPS)\nLLM open source gpt-oss','ai'),
 'WM':('Wazuh Manager\nrègles · corrélation · MITRE','bad'),
 'WI':('Wazuh Indexer\nmoteur OpenSearch','db'),
 'WD':('Wazuh Dashboard','bad'),
 'GRAF':('Grafana\nKPI banque et risque','ok'),
},[('SPA','PROXY'),('CHAT','PROXY'),('ATM','PROXY'),('PROXY','API'),('API','DB'),('API','KV'),('API','LLM','outils contrôlés'),
   ('WORKER','DB'),('WORKER','LOGS'),('WORKER','WI','rlbank-events-*'),('WORKER','MAIL'),('LOGS','WM'),('WM','WI'),('WD','WI'),
   ('WM','API','alertes signées HMAC',"dashed=1;"),('GRAF','DB'),('GRAF','WI')],
 [('nav','Navigateurs - poste de démonstration',['SPA','CHAT','ATM']),('core','Profil Docker : core',['API','WORKER','DB','KV','LOGS','MAIL']),
  ('ext','Service externe (offre gratuite)',['LLM']),('siem','Profil : siem',['WM','WI','WD']),('obs','Profil : observability',['GRAF'])],
 title='RL EXPRESS BANK — Architecture technique'))

# 2 Chaîne
pages.append(flow('2. Chaîne de traitement','LR',{
 'R':('Requête','grey'),'M1':('Request-ID\nen-têtes','box'),'M2':('Rate limiting','box'),'M3':('Authentification\nJWT + session active','box'),
 'M4':('Contexte appareil\net localisation','box'),'M5':('Autorisation\npermission + propriété','box'),'M6':('Validation Pydantic','box'),
 'M7':('Service métier','box'),'M8':('Risk Engine','ai'),'M9':('Policy Engine','dec'),'M10':('Exécution atomique\ntransaction SQL','ok'),
 'M11':('Challenge step-up\nlié à l\'opération','box'),'M12':('BLOCKED\n+ actions de réponse','bad'),'M13':('Outbox\névénements + audit','db')},
 [('R','M1'),('M1','M2'),('M2','M3'),('M3','M4'),('M4','M5'),('M5','M6'),('M6','M7'),('M7','M8'),('M8','M9'),
  ('M9','M10','ALLOW'),('M9','M11','STEP_UP'),('M9','M12','BLOCK'),('M10','M13'),('M11','M13'),('M12','M13')],
 title='Chaîne de traitement d\'une opération sensible', ranksep=0.5))

# 3 Rôles
pages.append(flow('3. Rôles','LR',{
 'C':('CLIENT','box'),'BOT':('RL SOLUTION\nagit avec les droits du client','ai'),
 'SA':('SUPER_ADMIN','bad'),'AN':('SECURITY_ANALYST','bad'),'AU':('AUDITOR','grey'),'SUP':('SUPPORT_AGENT','ok'),
 'P1':('Opérations sur SES ressources','grey'),'P2':('Sa sécurité\nMFA · passkeys · appareils · sessions','grey'),
 'P8':('Conversations assignées\nlecture masquée limitée dans le temps','grey'),'P3':('Détection et réponse\nalertes · investigations · actions','grey'),
 'P5':('Lecture seule complète\naudit · transactions · événements','grey'),'P6':('Administration\nutilisateurs · rôles · politiques · ATM','grey'),
 'P7':('Simulation Center','grey')},
 [('C','P1'),('C','P2'),('C','BOT'),('BOT','SUP','transfert'),('BOT','AN','signal de fraude'),('SUP','P8'),('AN','P3'),('AU','P5'),('SA','P6'),('SA','P7')],
 [('cli','Espace client',['C','BOT']),('staff','Personnel de la banque - comptes distincts',['SA','AN','AU','SUP'])],
 title='Rôles et périmètres'))

# 4 Parcours client
pages.append(flow('4. Parcours client','TB',{
 'A':('Accès https://bank.localhost','grey'),'B':('Login email + mot de passe','box'),'C':('Appareil connu ?\nRisque login ?','dec'),
 'D':('MFA selon politique','box'),'E':('NEW_DEVICE_LOGIN\nMFA obligatoire + notification','box'),'X':('Connexion refusée\nalerte SOC','bad'),
 'F':('Session créée, AAL enregistré','ok'),'G':('Dashboard','box'),'H1':('Comptes / RIB','grey'),'H2':('Virements / Bénéficiaires','grey'),
 'H3':('Carte / Paiements','grey'),'H4':('Retraits','grey'),'H5':('Sécurité et appareils','grey'),'H6':('Aide : RL SOLUTION','ai'),
 'I':('Opération sensible','box'),'J':('Risk + Policy','dec'),'K':('Exécutée + notification','ok'),'L':('TOTP / passkey','box'),
 'M':('Refus neutre + alerte SOC','bad'),'N':('Historique, audit, événements','db')},
 [('A','B'),('B','C'),('C','D','connu, LOW'),('C','E','nouvel appareil'),('C','X','CRITICAL'),('D','F'),('E','F'),('F','G'),
  ('G','H1'),('G','H2'),('G','H3'),('G','H4'),('G','H5'),('G','H6'),('H2','I'),('H3','I'),('H4','I'),('I','J'),
  ('J','K','ALLOW'),('J','L','STEP_UP'),('L','K'),('J','M','BLOCK'),('M','H6','aide'),('K','N'),('M','N')],
 title='Parcours client'))

# 5 Virement
pages.append(seq('5. Virement',[('C','Client','actor'),('UI','SPA',''),('API','API /transfers',''),('AZ','AuthZ',''),('RE','Risk Engine',''),('PE','Policy Engine',''),('DB','PostgreSQL','')],[
 ('m','C','UI','Compte source, bénéficiaire, montant, motif'),('m','UI','API','POST /transfers + Idempotency-Key'),
 ('m','API','AZ','transfer:create:own, propriété, bénéficiaire ACTIVE'),('m','API','DB','Réservation de la clé d\'idempotence'),
 ('m','API','DB','Transfer PENDING + TRANSFER_CREATED'),('m','API','RE','Contexte : montant, bénéficiaire, appareil, vélocité'),
 ('r','RE','API','Score, niveau, raisons'),('m','API','PE','Décision'),
 ('alt','ALLOW'),('m','API','DB','FOR UPDATE, solde, débit, grand livre, COMPLETED, outbox'),('r','API','UI','201 COMPLETED'),
 ('else','STEP_UP'),('m','API','DB','Challenge lié au transfer_id + hash'),('r','API','UI','202 step_up_required'),('m','C','UI','TOTP ou passkey'),
 ('m','UI','API','POST /transfers/:id/confirm'),('m','API','DB','Vérification puis exécution atomique'),('r','API','UI','200 COMPLETED'),
 ('else','BLOCK'),('m','API','DB','BLOCKED + TRANSFER_BLOCKED + alerte'),('r','API','UI','403 message neutre'),('end',)],
 title='Virement'))

# 6 Paiement
pages.append(seq('6. Paiement carte',[('C','Client','actor'),('TPE','Terminal marchand simulé',''),('API','API /payments',''),('RE','Risk Engine',''),('PE','Policy Engine',''),('DB','PostgreSQL','')],[
 ('m','C','TPE','Commerçant, catégorie, pays, ville, montant'),('m','TPE','API','POST /payments + jeton carte + Idempotency-Key'),
 ('m','API','DB','Carte ACTIVE, non expirée, compte ACTIVE, plafond'),
 ('alt','Carte bloquée, plafond ou solde insuffisant'),('m','API','DB','CARD_PAYMENT_DECLINED'),('r','API','TPE','DECLINED'),
 ('else','Contrôles OK'),('m','API','DB','CARD_PAYMENT_CREATED'),('m','API','RE','Catégorie, pays, montant, vélocité, heure'),('r','RE','API','Score et raisons'),('m','API','PE','Décision'),
 ('alt','ALLOW'),('m','API','DB','Débit, APPROVED'),('else','STEP_UP 3-D Secure simulé'),('r','API','C','Confirmation in-app TOTP ou passkey'),('m','C','API','Preuve liée au payment_id'),('m','API','DB','Débit, APPROVED'),
 ('else','BLOCK'),('m','API','DB','BLOCKED, verrouillage carte selon politique'),('end',),('r','API','TPE','Statut final'),('end',)],
 title='Paiement par carte'))

# 7 Retrait carte
pages.append(seq('7. Retrait avec carte',[('C','Client','actor'),('ATM','Kiosque ATM',''),('API','API /atm-terminal',''),('RE','Risk Engine',''),('PE','Policy Engine',''),('APP','App client',''),('DB','PostgreSQL','')],[
 ('m','ATM','API','Authentification du terminal ATM-DLA-004'),('m','API','DB','ATM ONLINE ? sinon refus'),('m','C','ATM','Carte simulée + PIN simulé'),
 ('m','ATM','API','Vérification du PIN haché, 3 essais max'),('m','C','ATM','Montant'),('m','ATM','API','POST retrait CARD + Idempotency-Key'),
 ('m','API','DB','Withdrawal PENDING + WITHDRAWAL_CREATED'),('m','API','RE','ATM habituel, heure, montant, vélocité'),('r','RE','API','Score'),('m','API','PE','Décision'),
 ('alt','ALLOW'),('m','API','DB','Verrou, solde, plafond, débit, APPROVED'),('r','API','ATM','Distribuer'),
 ('else','STEP_UP hors bande'),('m','API','APP','Approbation avec montant et ATM'),('r','ATM','C','Confirmez sur votre application'),('m','C','APP','TOTP ou passkey'),
 ('m','APP','API','Preuve liée au withdrawal_id'),('m','API','DB','Exécution atomique, APPROVED'),('r','API','ATM','Distribuer'),
 ('else','BLOCK'),('m','API','DB','BLOCKED, UNUSUAL_WITHDRAWAL_DETECTED'),('r','API','ATM','Opération impossible'),('end',)],
 title='Retrait avec carte', gap=240))

# 8 Retrait sans carte
pages.append(seq('8. Retrait sans carte',[('C','Client (app)','actor'),('API','API',''),('RE','Risk Engine',''),('PE','Policy Engine',''),('DB','PostgreSQL',''),('P','Porteur du code','actor'),('ATM','Kiosque ATM','')],[
 ('m','C','API','POST /withdrawals/cardless + Idempotency-Key'),('m','API','RE','Évaluation initiale'),('r','RE','API','Score'),
 ('m','API','PE','Décision (plancher : MFA toujours)'),('m','C','API','Preuve TOTP ou passkey liée à l\'opération'),
 ('m','API','DB','Verrou compte, hold des fonds, code généré'),('r','API','C','Référence + code affichés une fois, 15 min'),
 ('note','DB','DB','Stocké : HMAC(code, clé serveur) — jamais en clair ni dans les logs'),
 ('r','C','P','Transmission hors système'),('m','P','ATM','Référence + code'),('m','ATM','API','Validation par le terminal'),
 ('m','API','DB','UPDATE SET USED WHERE ACTIVE et non expiré'),
 ('alt','Invalide, expiré, utilisé ou 3 échecs'),('m','API','DB','WITHDRAWAL_AUTHENTICATION_FAILED'),('r','API','ATM','Refus'),
 ('else','Valide'),('m','API','RE','Analyse finale : ville ATM, délai'),('m','API','PE','Décision finale'),('m','API','DB','Débit, libération du hold, APPROVED'),('r','API','ATM','Distribuer'),('end',)],
 title='Retrait sans carte', gap=240))

# 9 MFA
pages.append(seq('9. MFA - Passkey',[('U','Utilisateur','actor'),('B','Navigateur',''),('API','API /auth',''),('DB','PostgreSQL',''),('OS','Authentificateur local','')],[
 ('m','U','B','Email + mot de passe'),('m','B','API','POST /auth/login'),('m','API','DB','Verrouillage, vérification Argon2id'),
 ('note','API','API','Réponse identique si email inconnu (temps constant)'),('m','API','API','Risque login'),
 ('alt','MFA non requise'),('m','API','DB','Session AAL1'),
 ('else','TOTP'),('r','API','B','mfa_required + challenge_id'),('m','U','B','Code à 6 chiffres'),('m','B','API','POST /auth/mfa/totp'),('m','API','DB','MFA_SUCCESS / FAILURE / LOCKOUT'),
 ('else','Passkey'),('r','API','B','Options WebAuthn : challenge, rpId'),('m','B','OS','navigator.credentials.get'),('m','OS','U','Biométrie ou PIN (local)'),
 ('r','OS','B','Assertion signée'),('m','B','API','POST /auth/passkey/verify'),('m','API','DB','Signature, origine, rpId, sign_count'),('end',),
 ('m','API','DB','Session : sid, device_id, aal, amr + USER_LOGIN'),('r','API','B','Access token (mémoire) + refresh (cookie httpOnly)')],
 title='Authentification MFA / Passkey', gap=300))

# 10 Risk → Policy
pages.append(flow('10. Risk vers Policy','TB',{
 'OP':('Opération','grey'),'CTX':('RiskContext','box'),'F1':('Signaux temps réel\nvélocité 1h / 24h','box'),'F2':('Profil comportemental\nprécalculé','box'),
 'F3':('Signaux RL SOLUTION\narnaque déclarée','ai'),'RULES':('Règles versionnées','box'),'AI':('Isolation Forest','ai'),'AGG':('Score 0 à 100 + raisons','box'),
 'LVL':('Niveau','dec'),'L':('LOW 0-30','ok'),'M':('MEDIUM 31-60','box'),'H':('HIGH 61-80','bad'),'CR':('CRITICAL 81-100','bad'),'POL':('Policy Engine\nopération × niveau × planchers','dec'),
 'D1':('ALLOW','ok'),'D3':('STEP_UP TOTP','box'),'D4':('STEP_UP PASSKEY','box'),'D5':('BLOCK + actions','bad'),
 'ACT':('Révoquer session · verrouiller carte\nannuler codes · bloquer appareil\nalerte SOC · notification','bad'),'RA':('risk_assessments','db')},
 [('OP','CTX'),('CTX','F1'),('CTX','F2'),('CTX','F3'),('F1','RULES'),('F2','RULES'),('F3','RULES'),('F2','AI'),('AI','AGG','max +15'),('RULES','AGG'),
  ('AGG','LVL'),('AGG','RA'),('LVL','L'),('LVL','M'),('LVL','H'),('LVL','CR'),('L','POL'),('M','POL'),('H','POL'),('CR','POL'),
  ('POL','D1'),('POL','D3'),('POL','D4'),('POL','D5'),('D5','ACT')], title='Risk Engine vers Policy Engine'))

# 11 Behavioral AI
pages.append(flow('11. Behavioral AI','LR',{
 'H':('Historique\nseed + opérations','db'),'SYN':('Générateur synthétique\nfraudes étiquetées','box'),'FB':('Feature builder\n(code partagé)','box'),
 'TR':('Entraînement\nIsolation Forest','ai'),'EV':('Évaluation\nprécision · rappel · PR-AUC','box'),'REG':('ml_models','db'),
 'OP':('Opération','grey'),'PROF':('behavior_profiles','db'),'FB2':('Même feature builder','box'),'SC':('Scoring en mémoire','ai'),
 'NORM':('Normalisation 0 à 1','box'),'PTS':('0 à +15 points\n+ variables déviantes','box'),'RE':('Risk Engine','box'),'JOB':('Job périodique','grey')},
 [('H','FB'),('SYN','FB'),('FB','TR'),('TR','EV'),('EV','REG'),('OP','FB2'),('PROF','FB2'),('FB2','SC'),('REG','SC','activation'),('SC','NORM'),('NORM','PTS'),('PTS','RE'),('JOB','PROF')],
 [('off','Hors ligne : worker ou notebook',['H','SYN','FB','TR','EV','REG']),('on','En ligne : API synchrone',['OP','PROF','FB2','SC','NORM','PTS','RE'])],
 title='Behavioral AI'))

# 12 Wazuh → SOC
pages.append(flow('12. Wazuh vers SOC','TB',{
 'APP':('API + Worker','box'),'JL':('rlbank-events.jsonl','file'),'IDX':('rlbank-events-*','db'),'WM':('Wazuh Manager\ndécodeur JSON natif','bad'),
 'R1':('Règles unitaires','grey'),'R2':('Règles de fréquence\n5 LOGIN_FAILED en 2 min','grey'),'R3':('Règles de séquence\nNEW_DEVICE → BENEFICIARY → gros retrait','grey'),
 'AL':('wazuh-alerts-*\n+ tags MITRE','db'),'WD':('Wazuh Dashboard','bad'),'HOOK':('API /integrations/wazuh/alerts','box'),
 'CORR':('Corrélation interne','box'),'ALERTS':('security_alerts','db'),'BOT':('RL SOLUTION\nsignal d\'arnaque','ai'),
 'SOC':('Dashboard SOC\ntriage · timeline · investigation','ok'),'ACT':('Actions de sécurité','bad'),'GRAF':('Grafana','ok')},
 [('APP','JL','outbox'),('APP','IDX','outbox'),('JL','WM'),('WM','R1'),('WM','R2'),('WM','R3'),('R1','AL'),('R2','AL'),('R3','AL'),('AL','WD'),
  ('WM','HOOK','niveau 10+, HMAC'),('APP','CORR'),('CORR','ALERTS'),('HOOK','ALERTS','dédoublonnage'),('BOT','ALERTS'),('ALERTS','SOC'),('SOC','ACT'),
  ('ACT','APP','SECURITY_ACTION_EXECUTED',"dashed=1;"),('IDX','GRAF')], title='Wazuh vers SOC'))

# 13 Compromission
pages.append(seq('13. Compromission',[('SIM','Moteur de simulation',''),('APP','RL Express Bank',''),('RE','Risk + Policy',''),('WZ','Wazuh',''),('SOC','Analyste SOC',''),('V','Client légitime','actor'),('BOT','RL SOLUTION','')],[
 ('note','SIM','APP','Phase 2 : faux conseiller au téléphone, OTP obtenu par manipulation, aucun identifiant réel'),
 ('m','SIM','APP','01:55 LOGIN nouvel appareil, ville inhabituelle'),('m','APP','RE','Score 35 MEDIUM → MFA exigée'),
 ('m','SIM','APP','OTP extorqué → NEW_DEVICE_LOGIN'),('m','SIM','APP','02:05 BENEFICIARY_CREATED'),('m','SIM','APP','02:17 retrait sans carte 300 000 XAF'),
 ('m','APP','RE','Score 80 HIGH → step-up'),('note','RE','RE','Variante A (TOTP) : code émis. Variante B (passkey) : BLOCKED dès 02:17'),
 ('m','SIM','APP','02:21 retrait sans carte 250 000 XAF'),('m','APP','RE','Score 95 CRITICAL → BLOCK'),
 ('r','RE','APP','Session révoquée, appareil bloqué, codes annulés, alerte'),('m','SIM','APP','02:26 tentative 200 000 XAF'),('r','APP','SIM','Refus immédiat : appareil BLOCKED'),
 ('m','APP','WZ','Flux d\'événements'),('m','WZ','APP','02:28 règle de séquence, niveau 12, MITRE'),('m','SOC','APP','Timeline, raisons, actions'),
 ('m','V','BOT','Pourquoi mon compte est bloqué ?'),('r','BOT','V','Explication neutre + parcours de récupération'),('m','V','APP','Récupération avec passkey')],
 title='Scénario de compromission (démo jury)', gap=250))

# 14 RL SOLUTION
pages.append(flow('14. RL SOLUTION','TB',{
 'U':('Client\nwidget RL SOLUTION','grey'),'GW':('API /support','box'),'IN':('Garde-fous entrée\nmasquage OTP, codes, PIN, IBAN\ndétection d\'injection\nsignaux d\'arnaque','bad'),
 'ORCH':('Orchestrateur\nintention · contexte · historique','ai'),'RAG':('Fiches publiées\nFAQ, procédures','db'),'LLM':('Groq\nLLM open source hébergé','ai'),
 'TG':('Passerelle d\'outils\nliste blanche + schémas','box'),'AZ':('AuthZ\ndroits du client','box'),'SVC':('Services métier existants','box'),'RP':('Risk + Policy + step-up','box'),
 'CONF':('Carte de confirmation UI\n+ step-up si requis','box'),'OUT':('Garde-fous sortie\npas de secret · pas de promesse\nréponse fondée sur les sources','bad'),
 'HUM':('SUPPORT_AGENT','ok'),'SOC':('Alerte SOC\nsource SUPPORT','bad'),'EV':('Event Logger','db')},
 [('U','GW','SSE / HTTPS'),('GW','IN'),('IN','ORCH'),('ORCH','RAG'),('ORCH','LLM'),('LLM','TG','proposition d\'outil'),('TG','AZ'),('AZ','SVC'),('SVC','RP'),
  ('TG','CONF','écriture'),('ORCH','OUT'),('OUT','U'),('ORCH','HUM','transfert'),('IN','SOC','arnaque / injection'),('GW','EV')],
 title='RL SOLUTION — agent IA de service client'))

# 15 Modèle de données
ER=[('USERS','USER_ROLES','1','n'),('ROLES','USER_ROLES','1','n'),('ROLES','ROLE_PERMISSIONS','1','n'),('PERMISSIONS','ROLE_PERMISSIONS','1','n'),
 ('USERS','ACCOUNTS','1','n'),('ACCOUNTS','LEDGER_ENTRIES','1','n'),('ACCOUNTS','ACCOUNT_HOLDS','1','n'),('ACCOUNTS','CARDS','1','n'),
 ('USERS','BENEFICIARIES','1','n'),('ACCOUNTS','TRANSFERS','1','n'),('BENEFICIARIES','TRANSFERS','1','n'),('CARDS','CARD_PAYMENTS','1','n'),
 ('ACCOUNTS','WITHDRAWALS','1','n'),('CARDS','WITHDRAWALS','0..1','n'),('ATMS','WITHDRAWALS','1','n'),('WITHDRAWALS','CARDLESS_CODES','1','0..1'),
 ('USERS','DEVICES','1','n'),('DEVICES','SESSIONS','1','n'),('USERS','MFA_CONFIGURATIONS','1','0..1'),('USERS','RECOVERY_CODES','1','n'),
 ('USERS','PASSKEY_CREDENTIALS','1','n'),('USERS','STEP_UP_CHALLENGES','1','n'),('USERS','BEHAVIOR_PROFILES','1','0..1'),('USERS','RISK_ASSESSMENTS','1','n'),
 ('TRANSFERS','RISK_ASSESSMENTS','0..1','n'),('WITHDRAWALS','RISK_ASSESSMENTS','0..1','n'),('CARD_PAYMENTS','RISK_ASSESSMENTS','0..1','n'),
 ('USERS','SECURITY_EVENTS','1','n'),('SECURITY_ALERTS','ALERT_EVENTS','1','n'),('SECURITY_EVENTS','ALERT_EVENTS','1','n'),('SECURITY_ALERTS','SECURITY_ACTIONS','1','n'),
 ('INVESTIGATIONS','SECURITY_ALERTS','1','n'),('USERS','SUPPORT_CONVERSATIONS','1','n'),('SUPPORT_CONVERSATIONS','SUPPORT_MESSAGES','1','n'),
 ('SUPPORT_CONVERSATIONS','SUPPORT_TOOL_CALLS','1','n'),('SUPPORT_CONVERSATIONS','SUPPORT_TICKETS','1','0..1'),
 ('USERS','AUDIT_LOGS','1','n'),('USERS','NOTIFICATIONS','1','n')]
ents={}
for a,b,_,_ in ER: ents[a]=(a,'entity'); ents[b]=(b,'entity')
ARR={'1':'ERmandOne','0..1':'ERzeroToOne','n':'ERzeroToMany'}
pages.append(flow('15. Modèle de données','LR',ents,[(a,b,'',f'startArrow={ARR[s]};endArrow={ARR[e]};startFill=0;endFill=0;') for a,b,s,e in ER],
 title='Modèle de données (entités principales)', ranksep=1.1, nodesep=0.35))

# 16 Roadmap (mise en page manuelle en colonnes)
rp=Page('16. Roadmap')
rp.vertex(lab('Roadmap RL EXPRESS BANK'),'text;html=1;fontSize=20;fontStyle=1;align=left;',40,10,800,40)
cols=[('Socle',[('1 Architecture','ok'),('2 Infrastructure','box'),('3 Database','box'),('4 Authentication','box'),('5 RBAC','box')]),
      ('Banque',[('6 Banking core','box'),('7 Carte','box'),('8 ATM','box')]),
      ('Sécurité et risque',[('9 MFA, passkeys','box'),('10 Événements','box'),('11 Risk, Policy','box'),('Tranche verticale\ndémontrable','dec')]),
      ('Détection et IA',[('12 IA','ai'),('13 SOC','box'),('13B RL SOLUTION','ai'),('14 Wazuh','bad'),('15 OpenSearch, Grafana','box'),('16 MITRE','box')]),
      ('Finalisation',[('17 Simulations','box'),('18 Tests','box'),('19 Documentation','box')])]
ids=[]; x=40
for cname,items in cols:
    cw=260; ch=60+len(items)*110
    c=rp.vertex(lab(cname),CLUSTER,x,70,cw,ch)
    for i,(t,k) in enumerate(items):
        w,h=(220,70) if k=='dec' else (220,60)
        ids.append(rp.vertex(lab(t),STYLES[k],20,50+i*110,w,h,parent=c))
    x+=cw+60
for a,b in zip(ids,ids[1:]):
    rp.edge('','html=1;endArrow=block;endFill=1;strokeColor=#4D4D4D;edgeStyle=orthogonalEdgeStyle;rounded=1;',a,b)
pages.append(rp)

xml='<?xml version="1.0" encoding="UTF-8"?>\n<mxfile host="app.diagrams.net" agent="RL EXPRESS BANK generator" version="24.7.0">'+''.join(p.xml() for p in pages)+'</mxfile>'
open('rl-express-bank-architecture.drawio','w',encoding='utf-8').write(xml)
print(len(pages),'pages', len(xml)//1024,'KB')
