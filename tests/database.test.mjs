import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';

test('schema, participant privacy, admin authorization, validation and atomic save', async () => {
  const db = new PGlite();
  try {
    await db.exec(`create role anon; create role authenticated; create schema auth;
      create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
      grant usage on schema auth to anon, authenticated;
      grant execute on function auth.jwt() to anon, authenticated;`);
    const schema = await readFile('supabase-schema.sql', 'utf8');
    await db.exec(schema);
    assert.deepEqual((await db.query('select * from certificate_settings')).rows, []);
    await db.exec(`insert into form_roles(form_id,role_id,label) values (1,'guest-speaker','Guest Speaker');
      insert into certificate_settings(id,event_role,template_type,template_data,name_font_size)
        values (1,'guest-speaker','custom_pdf','data:application/pdf;base64,AAAA',45);`);
    await db.exec(schema);
    assert.equal((await db.query('select name_font_size from certificate_settings')).rows[0].name_font_size, 45);
    await db.exec('set role anon');
    const questions = (await db.query('select * from survey_questions order by sort_order')).rows;
    const answers = Object.fromEntries(questions.map(q => [q.question_text, q.question_type === 'rating' ? '5' : q.question_type === 'choice' ? q.options[0] : 'Thank you']));
    await assert.rejects(db.query("insert into form_roles(form_id,label) values (1,'Blocked')"), /permission denied/);
    await assert.rejects(db.query(
      "insert into survey_responses(full_name,email,answers) values ('Student','student@example.com',$1)",
      [JSON.stringify(answers)]
    ), /Choose a role/);
    await assert.rejects(db.query(
      "insert into survey_responses(full_name,email,answers,event_role) values ('Student','student@example.com',$1,'invalid')",
      [JSON.stringify(answers)]
    ), error => error.code === '22023');
    await db.query("insert into survey_responses(full_name,email,answers,event_role) values ($1,$2,$3,'guest-speaker')", ['Student Name', 'STUDENT@example.com', JSON.stringify(answers)]);
    await assert.rejects(db.query('select * from survey_responses'), /permission denied/);
    await assert.rejects(db.query("update form_settings set form_title='Hacked'"), /permission denied/);
    await assert.rejects(db.query('insert into survey_responses(full_name,email,answers) values ($1,$2,$3)', ['Other Student', 'student@example.com', JSON.stringify(answers)]), error => error.code === '23505');
    await assert.rejects(db.query("insert into survey_responses(full_name,email,answers) values ('Student','bad@example.com','{}')"), /required questions/);
    await db.exec('reset role; set role authenticated');
    assert.equal((await db.query('select * from survey_responses')).rows.length, 0);
    assert.equal((await db.query("update form_roles set is_active=false returning role_id")).rows.length, 0);
    const rows = questions.map((q, index) => ({ ...q, sort_order: index + 1 }));
    await assert.rejects(db.query('select save_survey($1,$2,$3)', ['Blocked', '', JSON.stringify(rows)]), /Administrator access required/);
    await db.query("select set_config('request.jwt.claims', $1, false)", ['{"app_metadata":{"role":"admin"}}']);
    assert.equal((await db.query('select * from survey_responses')).rows.length, 1);
    await db.query('select save_survey($1,$2,$3)', ['Updated event', 'Council event', JSON.stringify(rows)]);
    assert.equal((await db.query('select form_title from form_settings')).rows[0].form_title, 'Updated event');
    rows[1].question_type = 'invalid';
    await assert.rejects(db.query('select save_survey($1,$2,$3)', ['Must rollback', '', JSON.stringify(rows)]));
    assert.equal((await db.query('select form_title from form_settings')).rows[0].form_title, 'Updated event');
    assert.equal((await db.query('select * from survey_questions')).rows.length, 4);
    await db.exec('reset role; set role anon');
    await assert.rejects(db.query('select * from response_email_registry'), /permission denied/);
    await assert.rejects(db.query("update form_settings set allow_duplicate_responses=true"), /permission denied/);
    await db.exec('reset role; set role authenticated');
    await db.query("select set_config('request.jwt.claims', '{}', false)");
    assert.equal((await db.query('update form_settings set allow_duplicate_responses=true returning id')).rows.length, 0);
    await db.query("select set_config('request.jwt.claims', $1, false)", ['{"app_metadata":{"role":"admin"}}']);
    await db.exec(`update form_settings set allow_duplicate_responses=true;
      update form_roles set label='Keynote Speaker' where role_id='guest-speaker';`);
    await db.exec('reset role; set role anon');
    await db.query("insert into survey_responses(full_name,email,answers,event_role) values ($1,$2,$3,'guest-speaker')", ['Repeat Student', ' STUDENT@example.com ', JSON.stringify(answers)]);
    await db.exec('reset role');
    assert.equal((await db.query('select count(*)::int as total from survey_responses')).rows[0].total, 2);
    assert.deepEqual((await db.query('select event_role from survey_responses order by created_at')).rows.map(row => row.event_role), ['guest-speaker', 'guest-speaker']);
    assert.equal((await db.query("select label from form_roles where role_id='guest-speaker'")).rows[0].label, 'Keynote Speaker');
    await db.exec("update form_settings set allow_duplicate_responses=false; update form_roles set is_active=false; set role anon");
    await assert.rejects(db.query(
      "insert into survey_responses(full_name,email,answers,event_role) values ('Archived','archived@example.com',$1,'guest-speaker')",
      [JSON.stringify(answers)]
    ), /no longer available/);
    await assert.rejects(db.query('insert into survey_responses(full_name,email,answers) values ($1,$2,$3)', ['Repeat Student', 'student@example.com', JSON.stringify(answers)]), error => error.code === '23505');
    // A rejected response must not consume an email's first valid submission.
    await assert.rejects(db.query("insert into survey_responses(full_name,email,answers) values ('Test','retry@example.com','{}')"), /required questions/);
    await db.query('insert into survey_responses(full_name,email,answers) values ($1,$2,$3)', ['Retry Student', 'retry@example.com', JSON.stringify(answers)]);
    await db.exec('reset role');
    // Upgrades and schema reruns preserve existing duplicate rows and settings.
    await db.exec(await readFile('migrations/20261025_allow_duplicate_responses.sql', 'utf8'));
    await db.exec(schema);
    assert.equal((await db.query('select count(*)::int as total from survey_responses')).rows[0].total, 3);
    await db.exec('set role anon');
    await assert.rejects(db.query('insert into survey_responses(full_name,email,answers) values ($1,$2,$3)', ['Repeat Student', 'STUDENT@example.com', JSON.stringify(answers)]), error => error.code === '23505');
  } finally { await db.close(); }
});

test('migration upgrades an existing database without losing responses or duplicate protection', async () => {
  const db = new PGlite();
  try {
    await db.exec(`create role anon; create role authenticated; create schema auth;
      create function auth.jwt() returns jsonb language sql stable as $$ select '{}'::jsonb $$;
      grant usage on schema auth to anon, authenticated;
      grant execute on function auth.jwt() to anon, authenticated;`);
    const schema = await readFile('supabase-schema.sql', 'utf8');
    await db.exec(schema.split('-- Run once in Supabase SQL Editor')[0]);
    const questions = (await db.query('select * from survey_questions')).rows;
    const answers = JSON.stringify(Object.fromEntries(questions.map(q => [q.question_text,
      q.question_type === 'rating' ? '5' : q.question_type === 'choice' ? q.options[0] : 'Thanks'])));
    await db.query('insert into survey_responses(full_name,email,answers) values ($1,$2,$3)', ['Existing Student', 'existing@example.com', answers]);
    await db.exec(await readFile('migrations/20261025_allow_duplicate_responses.sql', 'utf8'));
    assert.equal((await db.query('select count(*)::int as total from survey_responses')).rows[0].total, 1);
    await db.exec('set role anon');
    await assert.rejects(db.query('insert into survey_responses(full_name,email,answers) values ($1,$2,$3)', ['Existing Student', 'EXISTING@example.com', answers]), error => error.code === '23505');
    await db.exec('reset role; update form_settings set allow_duplicate_responses=true');
    await db.exec(schema);
    assert.equal((await db.query('select allow_duplicate_responses from form_settings')).rows[0].allow_duplicate_responses, true);
    await db.exec('set role anon');
    await db.query("insert into survey_responses(full_name,email,answers,event_role) values ($1,$2,$3,'participant')", ['Existing Student', 'existing@example.com', answers]);
    await db.exec('reset role');
    assert.equal((await db.query('select count(*)::int as total from survey_responses')).rows[0].total, 2);
  } finally { await db.close(); }
});


test('separate programs preserve legacy data and isolate validation, email policy, edits and certificates', async () => {
  const db = new PGlite();
  try {
    await db.exec(`create role anon; create role authenticated; create schema auth;
      create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
      grant usage on schema auth to anon, authenticated;
      grant execute on function auth.jwt() to anon, authenticated;`);
    const schema = await readFile('supabase-schema.sql', 'utf8');
    // Start from the previous release, with a real response and custom certificate.
    await db.exec(schema.split('-- Multi-program upgrade.')[0]);
    const oldQuestions = (await db.query('select * from survey_questions order by sort_order')).rows;
    const oldAnswers = JSON.stringify(Object.fromEntries(oldQuestions.map(q => [q.question_text,
      q.question_type === 'rating' ? '5' : q.question_type === 'choice' ? q.options[0] : 'Thanks'])));
    await db.query("insert into survey_responses(full_name,email,answers) values ('Original Student','shared@example.com',$1)", [oldAnswers]);
    await db.exec("insert into certificate_settings(id,title,template_type,template_data) values (1,'Original certificate','custom_image','data:image/png;base64,AAAA')");
    await db.exec("alter table certificate_settings alter column template_type set default 'default'");
    const migration = await readFile('migrations/20261028_multiple_forms.sql', 'utf8');
    await db.exec(migration);
    await db.exec('set role anon');
    await assert.rejects(db.query("select create_survey('Unauthorized')"), /permission denied/);
    await db.exec('reset role; set role authenticated');
    await assert.rejects(db.query("select create_survey('Unauthorized')"), /Administrator access required/);
    await db.query("select set_config('request.jwt.claims', $1, false)", ['{"app_metadata":{"role":"admin"}}']);
    const id = (await db.query("select create_survey('October 29 Program') as id")).rows[0].id;
    assert.equal(id, 2);
    const questions = (await db.query('select * from survey_questions where form_id=$1 order by sort_order', [id])).rows;
    const answers = JSON.stringify({ [questions[0].question_text]: '5' });
    await db.exec('reset role; set role anon');
    await db.query("insert into survey_responses(form_id,full_name,email,answers) values ($1,'Returning Student','SHARED@example.com',$2)", [id, answers]);
    await assert.rejects(db.query("insert into survey_responses(form_id,full_name,email,answers) values ($1,'Returning Student','shared@example.com',$2)", [id, answers]), e => e.code === '23505');
    await assert.rejects(db.query("insert into survey_responses(form_id,full_name,email,answers) values ($1,'Wrong Form','wrong@example.com',$2)", [id, oldAnswers]), /form has changed/);
    await assert.rejects(db.query("insert into survey_responses(form_id,full_name,email,answers) values (999,'Unknown','unknown@example.com','{}')"));
    await assert.rejects(db.query('select * from survey_responses'), /permission denied/);
    await db.exec('reset role; set role authenticated');
    const changed = questions.map(q => ({ ...q, question_text: q.question_text + ' updated' }));
    await db.query('select save_survey($1,$2,$3,$4)', ['New program title', 'Details', JSON.stringify(changed), id]);
    await assert.rejects(db.query('select save_survey($1,$2,$3,$4)', ['Should rollback', '', JSON.stringify(oldQuestions), id]), /another form/);
    await db.query("update certificate_settings set title='New certificate' where id=$1", [id]);
    assert.equal((await db.query('select title from certificate_settings where id=1')).rows[0].title, 'Original certificate');
    assert.deepEqual((await db.query('select * from survey_questions where form_id=1 order by sort_order')).rows.map(q => q.question_text), oldQuestions.map(q => q.question_text));
    assert.equal((await db.query('select count(*)::int as n from survey_responses where form_id=1')).rows[0].n, 1);
    assert.equal((await db.query('select count(*)::int as n from survey_responses where form_id=$1', [id])).rows[0].n, 1);
    await db.exec('reset role');
    await db.exec(migration);
    const roleMigration = await readFile('migrations/20261115_custom_roles.sql', 'utf8');
    await db.exec(roleMigration);
    await db.exec(roleMigration);
    const bannerMigration = await readFile('migrations/20261121_form_banners.sql', 'utf8');
    await db.exec(bannerMigration);
    const questionsBeforeHeaderEdit = (await db.query('select * from survey_questions where form_id=$1 order by sort_order', [id])).rows;
    const banner = 'data:image/png;base64,AAAA';
    const description = '  Program details\n\n\tFirst item';
    const saveHeader = 'select save_survey_with_header($1,$2,$3,$4,$5)';
    await db.exec('set role anon');
    await assert.rejects(db.query(saveHeader, [id, 'Blocked', '', banner, null]), error => error.code === '42501');
    await db.exec('reset role; set role authenticated');
    await db.query(saveHeader, [id, 'Formatted title', description, banner, null]);
    await assert.rejects(db.query(saveHeader, [id, 'Invalid banner', '', 'data:image/svg+xml;base64,AAAA', JSON.stringify(changed)]), error => error.code === '23514');
    assert.deepEqual((await db.query('select * from survey_questions where form_id=$1 order by sort_order', [id])).rows, questionsBeforeHeaderEdit);
    await db.exec('reset role');
    await db.exec(bannerMigration);
    await db.exec(schema);
    assert.deepEqual((await db.query('select form_title,form_description,banner_image from form_settings where id=$1', [id])).rows,
      [{ form_title: 'Formatted title', form_description: description, banner_image: banner }]);
    assert.equal((await db.query('select banner_image from form_settings where id=1')).rows[0].banner_image, 'default');
    await db.query(saveHeader, [id, 'Formatted title', description, '', null]);
    assert.equal((await db.query('select banner_image from form_settings where id=$1', [id])).rows[0].banner_image, '');
    assert.deepEqual((await db.query('select id,event_role,title,template_type from certificate_settings')).rows,
      [{ id: 1, event_role: 'participant', title: 'Original certificate', template_type: 'custom_image' }]);
    const freshId = (await db.query("select create_survey('Fresh program') as id")).rows[0].id;
    assert.equal((await db.query('select banner_image from form_settings where id=$1', [freshId])).rows[0].banner_image, '');
    assert.deepEqual((await db.query('select * from form_roles where form_id=$1', [freshId])).rows, []);
    await db.exec('set role anon');
    await assert.rejects(db.query(
      "insert into survey_responses(form_id,full_name,email,answers,event_role) values ($1,'Cross form','cross@example.com',$2,'participant')",
      [freshId, answers]
    ), /no longer available/);
    await db.query("insert into survey_responses(form_id,full_name,email,answers) values ($1,'No role','norole@example.com',$2)", [freshId, answers]);
    await db.exec('reset role');
    assert.equal((await db.query('select count(*)::int as n from survey_responses')).rows[0].n, 3);
    assert.equal((await db.query('select count(*)::int as n from response_email_registry')).rows[0].n, 3);
    await db.query("select set_config('request.jwt.claims', '{}', false)");
    await assert.rejects(db.query("select create_survey('No role')"), e => e.code === '42501');
  } finally { await db.close(); }
});
