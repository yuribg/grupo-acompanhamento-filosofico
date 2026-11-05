# grupo-acompanhamento-filosofico
Grupo de Acompanhamento Filosófico - Teseu / Maat / Prometeu

https://yuribg.github.io/grupo-acompanhamento-filosofico/

## Autenticação

O acesso usa OpenID Connect com Authorization Code Flow + PKCE:

- Issuer: `https://auth.acropolebrasil.com.br/as/realms/oinabnb`
- Client ID: `gaf`
- Redirect URI: `https://gaf.oinabn.com.br/`
- Escopos: `openid profile email`

O cliente `gaf` precisa estar configurado no provedor como cliente público, com PKCE usando `S256`, a URI de redirecionamento acima permitida e a origem `https://gaf.oinabn.com.br` autorizada para requisições do navegador. Para executar o site no endereço de GitHub Pages, autorize também `https://yuribg.github.io/grupo-acompanhamento-filosofico/` como redirect URI e `https://yuribg.github.io` como origem. Outros domínios também precisam ser autorizados no provedor.

A autenticação controla a navegação no navegador; como o site é estático, ela não impede que alguém acesse diretamente os arquivos publicados. Conteúdo que precise de confidencialidade deve ser servido por um backend que valide os tokens.