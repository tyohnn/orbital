// 팩토리의 이름. `scripts/new-factory.mjs` 가 복사할 때 `NAME` 과 `APP` 을 바꾼다. 사람이 읽는 이름(`TITLE`)은 직접 고친다.
//
// | 이름 | 무엇 |
// |---|---|
// | `NAME` | 플러그인 · MCP 서버의 이름. 플러그인의 `plugin.json` 과 같아야 한다 |
// | `APP` | 레이어에 올리는 스캐폴드(앱)의 이름. 소문자 · 숫자 · 밑줄 24자 안 |
// | `VERSION` | 새 고객이 갈라지는 스캐폴드의 버전(태그) |
// | `TITLE` | 연결 화면과 카드에 보이는 팩토리의 이름 |
export const NAME = "starter";
export const APP = "starter";
export const VERSION = "v1";
export const TITLE = "내 팩토리";

/** 카드(화면)의 주소와, 카드가 `_meta` 에서 찾는 이름 */
export const CARD_URI = `ui://${NAME}/card.html`;
export const CARD_META = `${NAME}/card`;
export const ENTRY_META = `${NAME}/entry`;
