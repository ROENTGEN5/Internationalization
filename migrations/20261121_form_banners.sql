BEGIN;

-- Preserve the bundled artwork on existing programs. New programs start with no banner.
ALTER TABLE public.form_settings
  ADD COLUMN IF NOT EXISTS banner_image text NOT NULL DEFAULT 'default'
  CHECK (
    banner_image IN ('', 'default')
    OR (length(banner_image) <= 1398127
      AND banner_image ~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$')
  );
ALTER TABLE public.form_settings ALTER COLUMN banner_image SET DEFAULT '';

CREATE OR REPLACE FUNCTION public.save_survey_with_header(
  p_form_id integer, p_title text, p_description text, p_banner text, p_questions jsonb
)
RETURNS text LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
DECLARE saved_banner text;
BEGIN
  IF (auth.jwt() -> 'app_metadata' ->> 'role') IS DISTINCT FROM 'admin' THEN
    RAISE EXCEPTION 'Administrator access required.' USING ERRCODE = '42501';
  END IF;
  IF p_title IS NULL OR char_length(btrim(p_title)) NOT BETWEEN 1 AND 300
    OR p_description IS NULL OR char_length(p_description) > 10000 THEN
    RAISE EXCEPTION 'Invalid form settings.';
  END IF;

  -- A null question list leaves the existing questions untouched.
  IF p_questions IS NOT NULL THEN
    PERFORM public.save_survey(p_title, p_description, p_questions, p_form_id);
  END IF;
  UPDATE public.form_settings
    SET form_title = btrim(p_title), form_description = p_description,
        banner_image = coalesce(p_banner, banner_image), updated_at = now()
    WHERE id = p_form_id
    RETURNING banner_image INTO saved_banner;
  IF NOT FOUND THEN RAISE EXCEPTION 'Form not found.'; END IF;
  RETURN saved_banner;
END;
$$;
REVOKE ALL ON FUNCTION public.save_survey_with_header(integer, text, text, text, jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.save_survey_with_header(integer, text, text, text, jsonb) TO authenticated;

COMMIT;
