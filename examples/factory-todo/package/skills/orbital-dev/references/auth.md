# 로그인과 인가(Orbital Auth)

앱의 로그인 · 사용자 · MCP 의 인가는 레이어가 맡습니다. 앱은 화면을 그리고, 레이어가 실어 준 신원을 DB 에 넘기기만 합니다.
비밀번호 · 세션 · 토큰을 앱이 만들거나 저장하지 않습니다.

## 선언

```toml
[auth]
methods = ["email_link"]   # 메일로 가는 로그인 링크. "google" 을 더하면 Google 로그인(아래)
login_path = "/login"      # 로그인이 필요할 때 레이어가 사람을 보낼 화면
directory = ["manager"]    # orbital.users(다른 사용자 목록)를 읽을 업무 역할. 없으면 아무도 읽지 못한다

[auth.mcp]                 # MCP 클라이언트(Claude 같은)가 사람 대신 부르게 할 때만
service = "web"
path = "/mcp"
consent_path = "/oauth/consent"
```

**로그인 방법은 팩토리의 키가 있어야 운영에 오릅니다.** 레이어는 공용 발송 도메인도 공용 Google 클라이언트도 갖지 않습니다.
`email_link` 는 팩토리의 Resend 키와 보내는 주소가, `google` 은 팩토리의 Google 클라이언트가 있어야 합니다. 키가 없으면
`orbital preview` 의 「승격을 막는 것」에 「팩토리가 … 키를 넣지 않았습니다」가 나오고 승격 요청이 거절됩니다. **에이전트가 고칠 수 없는 일입니다.**
코드를 고치거나 선언에서 방법을 빼서 넘기지 말고, 사람에게 「팩토리의 관리자가 설정에 키를 넣어야 한다」고 알립니다.
키가 없어도 프리뷰는 서고, 프리뷰에서는 메일이 나가지 않습니다(씨앗 사용자로 들어갑니다).

`[auth.mcp]` 를 두면 레이어가 인가 서버가 되어 `/.well-known/oauth-*`, `/_orbital/oauth/*` 에 답합니다. 앱은 `/mcp` 에서
Bearer 토큰을 보지 않습니다. 레이어가 확인하고 신원으로 바꿔 넘깁니다.

## 화면

화면은 `@harmony/orbital/app` 을 씁니다. 스캐폴드에는 의존성 없이 뜨도록 `vendor/orbital-app.js` 로 실려 있고, 본보기가
`pages/login.html` · `pages/consent.html` 입니다. 이 함수들은 같은 주소의 `/_orbital/…` 만 부르고 열쇠도 토큰도 받지 않습니다.

- **로그인 화면은 이메일 주소만 다룹니다.** `sendLoginLink({ email, next })` 를 부르고 「메일함을 확인해 주세요」를 보입니다.
  비밀번호 칸을 만들지 않고, 초대받았는지를 화면에서 가르지 않습니다(레이어는 어느 주소에나 같은 답을 줍니다).
- **Google 로 들어가기**는 단추 하나입니다. `location.href = googleSignInUrl(next)` 로 보내면 레이어가 Google 에 다녀와
  `next` 로 돌려보냅니다. 선언의 `methods` 에 `google` 이 있고 운영일 때만 열립니다(프리뷰에서는 404).
  본보기 `pages/login.html` 에 숨긴 단추(`#google`)가 있으니 선언에 `google` 을 켤 때 `hidden` 을 지웁니다.
  같은 이메일이면 이메일 링크로 들어온 사람과 같은 사용자이고, 처음 오는 이메일은 이메일 링크처럼 초대(또는 `signup = "open"`)가 있어야 합니다.
- **들어오지 못하면** 레이어가 `login_path?error=<코드>` 로 돌려보냅니다. 코드는 `not_invited` · `unverified`(Google 이 확인하지 않은 이메일) ·
  `expired` · `used` · `other_browser` · `disabled` · `denied`(Google 에서 거절) · `unavailable` · `invalid` 입니다. 화면은 코드마다 사람이 할 일을 적습니다.
- **누가 들어왔는지**는 `me()` 로 봅니다. 로그인하지 않았으면 `null` 입니다. 나가기는 `logout()` 입니다.
- **동의 화면은 레이어가 말한 것을 보입니다.** `consentRequest(id)` 가 준 클라이언트 이름 · 돌아갈 곳 · 범위를 글자 그대로
  (`textContent`) 보이고, 거기에 없는 약속을 덧붙이지 않습니다.
- **`approve(id)` 는 사람이 「허락」을 눌렀을 때만 보냅니다.** 화면이 열리자마자, 또는 에이전트의 판단으로 보내지 않습니다.
  돌아온 `redirect` 로 브라우저를 보냅니다. 거절은 `deny(id)` 입니다.
- 연결 목록 화면은 `grants()` 와 `revokeGrant(id)` 로 만듭니다.

서버 코드는 `identityOf(request)` 로 신원 머리말을 꺼내 그대로 DB 에 넘깁니다. 풀거나 믿지 않습니다.

```js
`BEGIN; SELECT set_config('orbital.identity', ${literal(identity)}, true); …; COMMIT`
```

## 정책

행 단위 규칙은 신원에서 사람을 꺼내는 함수를 `(SELECT …)` 로 감싸 씁니다. 감싸면 문장마다 한 번만 돌고, 감싸지 않으면 행마다 돕니다.

```sql
CREATE POLICY own_card ON todo.card
    USING (owner = (SELECT orbital.subject()))
    WITH CHECK (owner = (SELECT orbital.subject()));
```

`orbital.role()` · `orbital.client()` 도 같습니다. 레이어가 두는 `orbital_role` 이라는 정책 이름은 쓰지 않습니다.

## 사용자를 가리키는 외래 키

앱의 표는 사용자를 `orbital_auth.users (id)` 로 가리킬 수 있습니다. 사용자 표를 읽거나 고치지는 못합니다.

```sql
owner text NOT NULL DEFAULT orbital.subject() REFERENCES orbital_auth.users (id)
```

사람의 이름이나 이메일이 필요하면 `orbital.me`(나) 와 `orbital.users`(`directory` 의 역할만) 뷰를 읽습니다.

## 프리뷰의 씨앗 사용자

프리뷰에는 `db/seed/users.toml` 의 사용자가 들어갑니다. 운영에는 들어가지 않습니다.

```toml
[[user]]
id = "u1"
email = "u1@example.test"
roles = ["member"]
```

씨앗 데이터의 SQL 은 이 식별자(`'u1'`)로 행의 주인을 적습니다. 그 사용자로 요청해 보려면 `orbital identity u1` 의 값을 `Cookie` 머리에 싣습니다.
