CREATE TABLE ledger.transfer (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    amount int NOT NULL
);
