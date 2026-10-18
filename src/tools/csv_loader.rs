//! CSV loader — converts CSV data into MISP attributes.

use std::fs;
use std::path::Path;

use crate::error::{MispError, MispResult};
use crate::models::attribute::MispAttribute;
use crate::validation;

/// Loads MISP attributes from CSV data.
///
/// Expected CSV columns: `type`, `value` (required), and optionally
/// `category`, `comment`, `to_ids`.
///
/// # Example
/// ```
/// use rustmisp::tools::csv_loader::CsvLoader;
///
/// let csv = "type,value,category\nip-src,1.2.3.4,Network activity\n";
/// let attrs = CsvLoader::from_string(csv).unwrap();
/// assert_eq!(attrs.len(), 1);
/// assert_eq!(attrs[0].attr_type, "ip-src");
/// ```
pub struct CsvLoader;

impl CsvLoader {
    /// Load attributes from a CSV file.
    pub fn from_file(path: impl AsRef<Path>) -> MispResult<Vec<MispAttribute>> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| {
            MispError::InvalidInput(format!(
                "Failed to read CSV file {}: {}",
                path.as_ref().display(),
                e
            ))
        })?;
        Self::from_string(&content)
    }

    /// Load attributes from a CSV string.
    ///
    /// Each row is validated independently: a malformed or invalid row (bad
    /// type, unknown category, or a type/category pair the MISP server would
    /// reject) is skipped and logged via `log::warn!` rather than aborting
    /// the whole import. An error is only returned when every attempted row
    /// failed, or the CSV structure itself is invalid (missing headers).
    pub fn from_string(csv_content: &str) -> MispResult<Vec<MispAttribute>> {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .trim(csv::Trim::All)
            .from_reader(csv_content.as_bytes());

        let headers = reader
            .headers()
            .map_err(|e| MispError::InvalidInput(format!("Failed to read CSV headers: {e}")))?
            .clone();

        let type_idx = headers.iter().position(|h| h == "type");
        let value_idx = headers.iter().position(|h| h == "value");
        let category_idx = headers.iter().position(|h| h == "category");
        let comment_idx = headers.iter().position(|h| h == "comment");
        let to_ids_idx = headers.iter().position(|h| h == "to_ids");

        let type_idx = type_idx.ok_or_else(|| {
            MispError::InvalidInput("CSV missing required 'type' column".to_string())
        })?;
        let value_idx = value_idx.ok_or_else(|| {
            MispError::InvalidInput("CSV missing required 'value' column".to_string())
        })?;

        let mut attributes = Vec::new();
        let mut row_errors: Vec<String> = Vec::new();

        for (row_num, result) in reader.records().enumerate() {
            let record = match result {
                Ok(record) => record,
                Err(e) => {
                    let msg = format!("CSV parse error at row {}: {e}", row_num + 2);
                    log::warn!("{msg}");
                    row_errors.push(msg);
                    continue;
                }
            };

            let attr_type = record.get(type_idx).unwrap_or("").trim();
            let value = record.get(value_idx).unwrap_or("").trim();

            if attr_type.is_empty() || value.is_empty() {
                continue;
            }

            let category = category_idx
                .and_then(|i| record.get(i))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());

            let category = match category {
                Some(c) => c.to_string(),
                None => validation::get_default_category(attr_type)
                    .unwrap_or("Other")
                    .to_string(),
            };

            // Validate the type/category pair together (not independently):
            // the MISP server rejects a syntactically valid type paired with
            // a syntactically valid category that doesn't allow it (e.g.
            // type=md5, category=Person).
            if let Err(e) = validation::validate_type_category_pair(attr_type, &category) {
                let msg = format!("Row {}: {e}", row_num + 2);
                log::warn!("{msg}");
                row_errors.push(msg);
                continue;
            }

            let comment = comment_idx
                .and_then(|i| record.get(i))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            let to_ids = to_ids_idx
                .and_then(|i| record.get(i))
                .map(|s| matches!(s.trim(), "1" | "true" | "True" | "yes"))
                .unwrap_or_else(|| validation::get_default_to_ids(attr_type).unwrap_or(false));

            let mut attr = MispAttribute::new(attr_type, &category, value);
            attr.comment = comment;
            attr.to_ids = to_ids;
            attributes.push(attr);
        }

        if attributes.is_empty() && !row_errors.is_empty() {
            return Err(MispError::InvalidInput(row_errors.join("; ")));
        }

        Ok(attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_basic_parse() {
        let csv = "type,value,category\nip-src,1.2.3.4,Network activity\ndomain,example.com,Network activity\n";
        let attrs = CsvLoader::from_string(csv).unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].attr_type, "ip-src");
        assert_eq!(attrs[0].value, "1.2.3.4");
        assert_eq!(attrs[0].category, "Network activity");
        assert_eq!(attrs[1].attr_type, "domain");
        assert_eq!(attrs[1].value, "example.com");
    }

    #[test]
    fn csv_default_category() {
        let csv = "type,value\nmd5,d41d8cd98f00b204e9800998ecf8427e\n";
        let attrs = CsvLoader::from_string(csv).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].category, "Payload delivery");
        assert!(attrs[0].to_ids);
    }

    #[test]
    fn csv_with_comment_and_to_ids() {
        let csv = "type,value,category,comment,to_ids\nip-src,1.2.3.4,Network activity,test comment,true\n";
        let attrs = CsvLoader::from_string(csv).unwrap();
        assert_eq!(attrs[0].comment, "test comment");
        assert!(attrs[0].to_ids);
    }

    #[test]
    fn csv_invalid_type() {
        let csv = "type,value\nnot-a-real-type,somevalue\n";
        assert!(CsvLoader::from_string(csv).is_err());
    }

    #[test]
    fn csv_invalid_category() {
        let csv = "type,value,category\nmd5,abc123,Fake category\n";
        assert!(CsvLoader::from_string(csv).is_err());
    }

    #[test]
    fn csv_rejects_mismatched_type_category_pair() {
        // Both `md5` and `Person` are individually valid, but MISP's
        // categoryDefinitions do not allow `md5` under `Person`
        // (see app/Model/MispAttribute.php categoryDefinitions[...]['types']
        // and the pair check at line ~997-998 in the pinned MISP checkout).
        // Before the fix, type and category were validated independently
        // and this row was accepted; the server would then reject it.
        let csv = "type,value,category\nmd5,d41d8cd98f00b204e9800998ecf8427e,Person\n";
        let err = CsvLoader::from_string(csv).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not valid for category"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn csv_skips_bad_rows_but_keeps_good_ones() {
        // Before the fix, a single malformed row aborted the whole import
        // and every successfully parsed row before it was discarded. Now
        // the bad row is skipped and the good row is still returned.
        let csv = "type,value\nmd5,d41d8cd98f00b204e9800998ecf8427e\nnot-a-real-type,somevalue\n";
        let attrs = CsvLoader::from_string(csv).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].attr_type, "md5");
        assert_eq!(attrs[0].value, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn csv_skips_empty_rows() {
        let csv = "type,value\nmd5,abc123\n,,\nsha1,def456\n";
        let attrs = CsvLoader::from_string(csv).unwrap();
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn csv_missing_type_column() {
        let csv = "value,category\nabc,Other\n";
        assert!(CsvLoader::from_string(csv).is_err());
    }

    #[test]
    fn csv_missing_value_column() {
        let csv = "type,category\nmd5,Other\n";
        assert!(CsvLoader::from_string(csv).is_err());
    }
}
