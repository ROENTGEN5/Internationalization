BEGIN;

LOCK TABLE public.form_settings, public.certificate_settings, public.survey_responses
  IN SHARE ROW EXCLUSIVE MODE;

-- Keep stable IDs for existing responses and custom templates.
ALTER TABLE public.survey_responses ADD COLUMN IF NOT EXISTS event_role text DEFAULT 'participant';
ALTER TABLE public.survey_responses
  DROP CONSTRAINT IF EXISTS survey_responses_event_role_check,
  ALTER COLUMN event_role DROP NOT NULL,
  ALTER COLUMN event_role DROP DEFAULT;
GRANT INSERT (event_role) ON public.survey_responses TO anon, authenticated;

ALTER TABLE public.certificate_settings ADD COLUMN IF NOT EXISTS event_role text NOT NULL DEFAULT 'participant';
ALTER TABLE public.certificate_settings
  DROP CONSTRAINT IF EXISTS certificate_settings_event_role_check,
  ALTER COLUMN event_role DROP DEFAULT,
  ALTER COLUMN template_type DROP DEFAULT,
  ALTER COLUMN title SET DEFAULT '',
  ALTER COLUMN issuer SET DEFAULT '',
  ALTER COLUMN body SET DEFAULT '',
  ALTER COLUMN signatory_name SET DEFAULT '',
  ALTER COLUMN signatory_title SET DEFAULT '';

CREATE TABLE IF NOT EXISTS public.form_roles (
  form_id integer NOT NULL REFERENCES public.form_settings(id),
  role_id text NOT NULL DEFAULT gen_random_uuid()::text,
  label text NOT NULL CHECK (label = btrim(label) AND char_length(label) BETWEEN 1 AND 100),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (form_id, role_id)
);

INSERT INTO public.form_roles (form_id, role_id, label)
SELECT form_id, role_id, initcap(role_id) FROM (
  SELECT id AS form_id, event_role AS role_id FROM public.certificate_settings
  UNION
  SELECT form_id, event_role FROM public.survey_responses WHERE event_role IS NOT NULL
) legacy
ON CONFLICT (form_id, role_id) DO NOTHING;

CREATE UNIQUE INDEX IF NOT EXISTS form_roles_active_label_idx
  ON public.form_roles (form_id, lower(label)) WHERE is_active;

ALTER TABLE public.form_roles ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.form_roles FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.form_roles TO anon, authenticated;
GRANT INSERT (form_id, role_id, label), UPDATE (label, is_active) ON public.form_roles TO authenticated;

DROP POLICY IF EXISTS "Public can read form roles" ON public.form_roles;
CREATE POLICY "Public can read form roles" ON public.form_roles FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "Admins can add form roles" ON public.form_roles;
CREATE POLICY "Admins can add form roles" ON public.form_roles FOR INSERT TO authenticated
  WITH CHECK ((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
DROP POLICY IF EXISTS "Admins can update form roles" ON public.form_roles;
CREATE POLICY "Admins can update form roles" ON public.form_roles FOR UPDATE TO authenticated
  USING ((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
  WITH CHECK ((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

ALTER TABLE public.survey_responses DROP CONSTRAINT IF EXISTS survey_responses_form_role_fk;
ALTER TABLE public.survey_responses ADD CONSTRAINT survey_responses_form_role_fk
  FOREIGN KEY (form_id, event_role) REFERENCES public.form_roles(form_id, role_id);

ALTER TABLE public.certificate_settings DROP CONSTRAINT IF EXISTS certificate_settings_pkey;
ALTER TABLE public.certificate_settings ADD PRIMARY KEY (id, event_role);
-- A legacy role could switch to the built-in frame while retaining an upload.
UPDATE public.certificate_settings
SET template_type = CASE WHEN template_data LIKE 'data:application/pdf%' THEN 'custom_pdf' ELSE 'custom_image' END
WHERE template_type = 'default'
  AND (template_data LIKE 'data:application/pdf%' OR template_data LIKE 'data:image/%');
DELETE FROM public.certificate_settings
WHERE template_type NOT IN ('custom_pdf', 'custom_image') OR coalesce(template_data, '') = '';

ALTER TABLE public.certificate_settings
  DROP CONSTRAINT IF EXISTS certificate_settings_form_role_fk,
  DROP CONSTRAINT IF EXISTS certificate_settings_uploaded_template;
ALTER TABLE public.certificate_settings
  ADD CONSTRAINT certificate_settings_form_role_fk
    FOREIGN KEY (id, event_role) REFERENCES public.form_roles(form_id, role_id),
  ADD CONSTRAINT certificate_settings_uploaded_template
    CHECK (template_type IN ('custom_pdf', 'custom_image') AND coalesce(template_data, '') <> '');

CREATE OR REPLACE FUNCTION public.validate_survey_role()
RETURNS trigger LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
  IF NEW.event_role IS NULL THEN
    IF EXISTS (SELECT 1 FROM public.form_roles WHERE form_id = NEW.form_id AND is_active) THEN
      RAISE EXCEPTION 'Choose a role from the form.' USING ERRCODE = '22023';
    END IF;
  ELSIF NOT EXISTS (
    SELECT 1 FROM public.form_roles
    WHERE form_id = NEW.form_id AND role_id = NEW.event_role AND is_active
  ) THEN
    RAISE EXCEPTION 'This role is no longer available. Reload the form and try again.' USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS validate_survey_role ON public.survey_responses;
CREATE TRIGGER validate_survey_role BEFORE INSERT ON public.survey_responses
  FOR EACH ROW EXECUTE FUNCTION public.validate_survey_role();

CREATE OR REPLACE FUNCTION public.create_survey(p_title text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE new_id integer;
BEGIN
  IF (auth.jwt() -> 'app_metadata' ->> 'role') IS DISTINCT FROM 'admin' THEN
    RAISE EXCEPTION 'Administrator access required.' USING ERRCODE = '42501';
  END IF;
  IF p_title IS NULL OR char_length(btrim(p_title)) NOT BETWEEN 1 AND 300 THEN
    RAISE EXCEPTION 'Enter a program title of 1 to 300 characters.';
  END IF;
  INSERT INTO public.form_settings(form_title, form_description)
    VALUES (btrim(p_title), 'Please share your feedback about this program.') RETURNING id INTO new_id;
  INSERT INTO public.survey_questions(form_id, question_text, question_type, is_required, sort_order)
    VALUES (new_id, 'How would you rate the overall program?', 'rating', true, 1),
      (new_id, 'What can we improve for future programs?', 'paragraph', false, 2);
  RETURN new_id;
END;
$$;
REVOKE ALL ON FUNCTION public.create_survey(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_survey(text) TO authenticated;

COMMIT;
