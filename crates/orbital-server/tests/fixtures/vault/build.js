// 빌드가 받은 환경 변수의 이름을 적어 둔다. 레이어가 빌드에 비밀을 건네지 않는지 테스트가 본다.
const fs = require("node:fs");

fs.writeFileSync("build-env.json", JSON.stringify({ names: Object.keys(process.env).sort() }));
