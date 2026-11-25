CREATE TABLE todo.card (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner text NOT NULL DEFAULT orbital.subject(),
    title text NOT NULL
);
ALTER TABLE todo.card ENABLE ROW LEVEL SECURITY;
CREATE POLICY mine ON todo.card
    USING (owner = (SELECT orbital.subject()))
    WITH CHECK (owner = (SELECT orbital.subject()));
