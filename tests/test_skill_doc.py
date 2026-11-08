import unittest
from pathlib import Path


class SkillDocTest(unittest.TestCase):
    def test_skill_frontmatter_and_safety_rules(self):
        text = Path("skills/mail-triage/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("name: mail-triage", text)
        self.assertIn("description:", text)
        self.assertIn("Nunca ejecutes `purge` sin", text)
        self.assertIn("--code", text)


if __name__ == "__main__":
    unittest.main()
