// `@harmony/orbital/app`: 팩토리의 앱이 Orbital Auth 를 쓰는 길.
//
// 브라우저 쪽 함수는 같은 주소의 `/_orbital/…` 만 부른다. 열쇠도 토큰도 받지 않는다. 사람은 레이어의 쿠키(`__Host-orbital-*`)로
// 알아보고, 그 쿠키는 브라우저가 싣는다. 서버 쪽 함수는 router 가 실어 준 서명된 신원 머리말을 글자 그대로 꺼낼 뿐이고,
// 그 값은 DB 에 넘겨 행 단위 규칙이 읽는다(`set_config('orbital.identity', 값, true)`).

/** 로그인한 사람. */
                   
 
               
                  
                        
                    
 

/** 동의 화면이 보일 것. 레이어가 말한 것만 보입니다. */
                               
 
                                                               
                     
                     
 

/** 사용자가 클라이언트 하나에 준 승인. */
                      
 
               
                                         
                      
 

/** 레이어가 요청을 거절했다. `code` 는 레이어의 오류 이름(`unauthorized` · `not_found` …)이다. */
export class OrbitalAppError extends Error
{
             status        ;
             code        ;

    constructor(status        , code        )
    {
        super(`레이어가 요청을 거절했습니다(${status} ${code})`);
        this.name = "OrbitalAppError";
        this.status = status;
        this.code = code;
    }
}

                                  
 
                                                                    
                    
                                            
                         
 

                           
 
                                                    
                                                                          
                                      
                             
                            
                                                        
                                                     
                                                       
                                                    
                               
                                           
 

function isRecord(value         )                                  
{
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value         )        
{
    return typeof value === "string" ? value : "";
}

function texts(value         )          
{
    return Array.isArray(value) ? value.filter((item)                 => typeof item === "string") : [];
}

/**
 * Google 로 들어가는 주소. 로그인 화면의 단추가 브라우저를 이리로 보낸다(`location.href = googleSignInUrl("/cards")`).
 * 선언의 `[auth].methods` 에 `google` 이 있고 운영일 때만 열린다. 미리보기와 팩토리가 Google 키를 넣지 않은 운영에서는 404 다.
 * 들어오지 못하면 레이어가 `login_path?error=<코드>` 로 돌려보낸다(`not_invited` · `unverified` · `expired` · `used` · `other_browser` · `denied` · `unavailable` · `invalid`).
 */
export function googleSignInUrl(next = "/", origin = "")        
{
    return `${origin}/_orbital/auth/google/start?next=${encodeURIComponent(next)}`;
}

export function orbitalApp(options                    = {})            
{
    const origin = options.origin ?? "";
    const send = options.fetch ?? ((input                   , init              ) => fetch(input, init));

    async function call(method        , path        , body          )                   
    {
        const headers                         = { accept: "application/json" };
        if (body !== undefined)
        {
            headers["content-type"] = "application/json";
        }
        const response = await send(`${origin}${path}`, {
            method,
            headers,
            body: body === undefined ? null : JSON.stringify(body),
            credentials: "same-origin",
        });
        if (!response.ok)
        {
            let code = "unknown";
            try
            {
                const answer          = await response.json();
                code = isRecord(answer) ? text(answer.error) || code : code;
            }
            catch
            {
                // 몸이 JSON 이 아니면 상태만 알린다
            }
            throw new OrbitalAppError(response.status, code);
        }
        return response;
    }

    async function json(method        , path        , body          )                                  
    {
        const answer          = await (await call(method, path, body)).json();
        return isRecord(answer) ? answer : {};
    }

    const request = (id        )         => `/_orbital/oauth/requests/${encodeURIComponent(id)}`;

    return {
        async sendLoginLink({ email, next })
        {
            await call("POST", "/_orbital/auth/email-link", { email, next: next ?? "/" });
        },
        async me()
        {
            try
            {
                const answer = await json("GET", "/_orbital/auth/me");
                return {
                    id: text(answer.id),
                    email: text(answer.email),
                    name: typeof answer.name === "string" ? answer.name : null,
                    roles: texts(answer.roles),
                };
            }
            catch (error)
            {
                if (error instanceof OrbitalAppError && error.status === 401)
                {
                    return null;
                }
                throw error;
            }
        },
        async logout()
        {
            await call("POST", "/_orbital/auth/logout");
        },
        async consentRequest(id)
        {
            const answer = await json("GET", request(id));
            const client = isRecord(answer.client) ? answer.client : {};
            return {
                client: { id: text(client.id), name: text(client.name), redirectHost: text(client.redirect_host) },
                scopes: texts(answer.scopes),
                resource: text(answer.resource),
            };
        },
        async approve(id)
        {
            return { redirect: text((await json("POST", `${request(id)}/approve`)).redirect) };
        },
        async deny(id)
        {
            return { redirect: text((await json("POST", `${request(id)}/deny`)).redirect) };
        },
        async grants()
        {
            const answer = await json("GET", "/_orbital/oauth/grants");
            const grants = Array.isArray(answer.grants) ? answer.grants.filter(isRecord) : [];
            return grants.map((grant) =>
            {
                const client = isRecord(grant.client) ? grant.client : {};
                return {
                    id: text(grant.id),
                    client: { id: text(client.id), name: text(client.name) },
                    createdAt: typeof grant.created_at === "number" ? grant.created_at : 0,
                };
            });
        },
        async revokeGrant(id)
        {
            await call("DELETE", `/_orbital/oauth/grants/${encodeURIComponent(id)}`);
        },
    };
}

const browser = orbitalApp();

export const sendLoginLink = browser.sendLoginLink;
export const me = browser.me;
export const logout = browser.logout;
export const consentRequest = browser.consentRequest;
export const approve = browser.approve;
export const deny = browser.deny;
export const grants = browser.grants;
export const revokeGrant = browser.revokeGrant;

/** router 가 실어 준 서명된 신원. 로그인하지 않은 요청이면 `null`. 값을 풀거나 믿지 말고 DB 에 그대로 넘깁니다. */
export function identityOf(request                                                                                )               
{
    const headers = request.headers;
    if (headers instanceof Headers)
    {
        return headers.get("x-orbital-identity");
    }
    const value = headers["x-orbital-identity"];
    return typeof value === "string" ? value : null;
}
