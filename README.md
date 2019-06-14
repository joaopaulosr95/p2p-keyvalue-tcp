# testes

- Servent detecta a queda de um peer e remove o socket da lista de peers corretamente ❌
- Servent detecta a queda de um client e remove o socket da lista de clients corretamente

## ID

- Servent detecta a queda de um cliente e remove o socket da lista de clients corretamente ✔️
- Cliente monta e envia o pacote ID corretamente ✔️
- Servent recebe e desmonta o pacote ID corretamente ✔️
- Servent identifica o client e salva o socket na lista de clients ✔️  

## KEYREQ

- Cliente monta e envia o pacote KEYREQ corretamente ✔️  
- Servent recebe e desmonta o pacote KEYREQ corretamente ✔️  
- Servent identifica a chave no banco corretamente ✔️
- Servent monta um pacote RESP e envia corretamente ✔️️
- Servent monta um pacote KEYFLOOD e encaminha corretamente ✔️
- Cliente recebe e desmonta o pacote RESP para o KEYREQ corretamente ✔️

## KEYFLOOD

- Servent recebe e desmonta o pacote KEYFLOOD corretamente ✔️
- Servent identifica a chave no banco corretamente ✔️
- Servent monta um pacote RESP e envia corretamente ✔️
- Servent decrementa o TTL e encaminha o KEYFLOOD corretamente ️️️✔️
- Cliente recebe e desmonta o pacote RESP para o KEYFLOOD corretamente ️️️️️️️✔️

## TOPOREQ

- Cliente monta e envia o pacote TOPOREQ corretamente ️✔️
- Servent recebe e desmonta o pacote corretamente ️✔️
- Servent monta um pacote RESP e envia corretamente com seu ip:porta anexo ao payload ️✔️
- Servent monta pacote TOPOFLOOD com seu ip:porta no info e envia corretamente ️✔️
- Cliente recebe e desmonta o pacote RESP para o TOPOREQ corretamente ️✔️

## TOPOFLOOD

- Servent recebe e desmonta o pacote corretamente ✔️
- Servent identifica a chave no banco corretamente ✔️
- Servent monta um pacote RESP e envia corretamente com seu ip:porta anexo ao payload ✔️
- Servent decrementa o TTL e encaminha o TOPOFLOOD corretamente ✔️
- Cliente recebe e desmonta o pacote RESP para o TOPOFLOOD corretamente ✔️
