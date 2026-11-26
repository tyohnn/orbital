import type { Refusal } from "@/server/dashboard";

/** 거절을 화면의 말로. */
export const REFUSALS: Record<Refusal, string> = {
    not_found: "찾을 수 없어요.",
    not_allowed: "이 일은 주인이나 관리자만 할 수 있어요.",
    invalid_name: "이름은 영어 소문자나 숫자로 시작하고, 소문자 · 숫자 · - · _ 로 64자까지 쓸 수 있어요.",
    invalid_email: "이메일 주소를 확인해 주세요.",
    invalid_label: "이름은 100자까지 쓸 수 있어요.",
    name_taken: "이미 쓰는 이름이에요. 다른 이름을 골라 주세요.",
    last_owner: "주인이 한 명은 있어야 해요. 다른 팀원을 주인으로 바꾼 뒤에 다시 해 주세요.",
    last_key: "마지막 키는 폐기할 수 없어요. 새 키를 만든 뒤에 폐기해 주세요.",
    dashboard_key: "대시보드가 쓰는 키라서 폐기할 수 없어요.",
};
