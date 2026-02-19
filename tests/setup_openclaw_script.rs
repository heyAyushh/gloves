#[cfg(unix)]
mod unix_tests {
    use assert_cmd::Command;
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    use tempfile::TempDir;

    const SKILL_USAGE: &str = "gloves-cli-usage";
    const SKILL_SETUP_MIGRATE: &str = "gloves-setup-migrate";

    fn setup_script_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-openclaw.sh")
    }

    fn write_skill(repo_root: &Path, skill_name: &str) {
        let skill_dir = repo_root.join("skills").join(skill_name);
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("SKILL.md"), format!("name: {skill_name}\n")).unwrap();
    }

    fn dry_run(repo_root: &Path, skills_dest: &Path) -> Command {
        let mut command = Command::new("bash");
        command
            .arg(setup_script_path())
            .arg("--repo-root")
            .arg(repo_root)
            .arg("--skip-cli-install")
            .arg("--skip-init")
            .arg("--dry-run")
            .arg("--skills-dest")
            .arg(skills_dest);
        command
    }

    #[test]
    fn setup_script_dry_run_uses_local_repo_for_both_skills() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        let skills_dest = temp.path().join("installed");

        write_skill(&repo_root, SKILL_USAGE);
        write_skill(&repo_root, SKILL_SETUP_MIGRATE);

        let assert = dry_run(&repo_root, &skills_dest).assert().success();
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

        assert!(stderr.contains(&format!(
            "Installing skill {SKILL_USAGE} to: {}",
            skills_dest.join(SKILL_USAGE).display()
        )));
        assert!(stderr.contains(&format!(
            "Installing skill {SKILL_SETUP_MIGRATE} to: {}",
            skills_dest.join(SKILL_SETUP_MIGRATE).display()
        )));
    }

    #[test]
    fn setup_script_summary_lists_both_installed_skill_targets() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        let skills_dest = temp.path().join("installed");

        write_skill(&repo_root, SKILL_USAGE);
        write_skill(&repo_root, SKILL_SETUP_MIGRATE);

        let assert = dry_run(&repo_root, &skills_dest).assert().success();
        let stdout = String::from_utf8_lossy(&assert.get_output().stdout);

        assert!(stdout.contains("Installed skills:"));
        assert!(stdout.contains(&format!("- {}", skills_dest.join(SKILL_USAGE).display())));
        assert!(stdout.contains(&format!(
            "- {}",
            skills_dest.join(SKILL_SETUP_MIGRATE).display()
        )));
    }

    #[test]
    fn setup_script_fails_when_explicit_repo_root_is_missing_a_required_skill() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        let skills_dest = temp.path().join("installed");

        write_skill(&repo_root, SKILL_USAGE);

        let assert = dry_run(&repo_root, &skills_dest).assert().failure();
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

        assert!(stderr.contains("repo root is missing required skills"));
        assert!(stderr.contains(SKILL_SETUP_MIGRATE));
    }
}
