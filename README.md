# Royal — conector fiscal em nuvem

Serviço separado para permitir a configuração e os testes de NFS-e pelo celular. Usa Node.js 24.5+ e OpenSSL. Não contém cadastros de clientes, dados financeiros, certificado, senha ou chave administrativa. O código ainda não emite notas: valida o certificado no servidor e realiza uma consulta de leitura em homologação.

## Render

Crie um Web Service Docker, plano Free de homologação, com esta pasta na raiz. A saúde técnica está em `/healthz`; as operações `/status` e `/test-connection` exigem sessão Supabase válida e administrador ativo. Escuta em `0.0.0.0:$PORT`.

Defina no ambiente privado `SUPABASE_URL`, a chave pública `SUPABASE_ANON_KEY` da Royal e `ALLOWED_ORIGINS` conforme `.env.example`. O projeto Supabase é exclusivamente `lvjctawcjtbbrdqdvefi`; o site atual permanece hospedado no Sites. Não crie outro banco no Render.

O certificado A1 e a senha serão instalados somente em segredos privados da hospedagem. Há suporte a `NFSE_PFX_BASE64_FILE` com `NFSE_PFX_PASSWORD_FILE`, ou às variáveis privadas `NFSE_PFX_BASE64` e `NFSE_PFX_PASSWORD`. Não envie esses valores para a conversa nem para o Git. A URL HTTPS pública do serviço, sem segredos, será conectada ao Royal por `NEXT_PUBLIC_NFSE_CONNECTOR_URL`.

O Free é somente para testes e tem suspensão por inatividade e limites de uso. Nenhum plano pago, disco, banco ou cron é necessário nesta etapa. Não usar a presença do servidor como confirmação de habilitação fiscal.

## Verificação

`npm test` gera certificado fictício descartável e testa certificado, autenticação, CORS e ausência de transmissão. Não usa A1 real ou emite nota. Depois de publicar, conferir `/healthz` 200, acesso administrativo, bloqueio da equipe/anônimo e certificado pendente; depois instalar o A1 privadamente e testar homologação.

A geração, assinatura, numeração, transmissão, reconciliação e guarda das notas ainda precisam ser implementadas e validadas. O cadastro fiscal e os códigos dos serviços precisam de conferência pelo responsável da empresa.

## Endpoint de parâmetros municipais

A consulta somente de leitura usa `GET https://adn.producaorestrita.nfse.gov.br/parametrizacao/{codigoMunicipio}/convenio`, com mTLS e validação da cadeia do servidor. O host e o método são fixos, não fornecidos pelo navegador; não há redirecionamento. A API de parâmetros é separada da Sefin Nacional. Referência oficial consultada em 01/11/2026: https://www.gov.br/nfse/pt-br/biblioteca/documentacao-tecnica/apis-prod-restrita-e-producao (Parâmetros municipais — Produção restrita). Esta correção substitui a antiga consulta no caminho SefinNacional, que retornava 404.
