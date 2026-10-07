use crate::core::error::SentryError;
use crate::core::models::{Chunk, Document};
use crate::core::traits::Chunker;

/// Recursive character text splitter that breaks text along semantic boundaries (paragraphs, sentences, words).
#[derive(Debug, Clone)]
pub struct RecursiveCharacterChunker {
    pub chunk_size: usize,
    pub chunk_overlap: usize,
    pub delimiters: Vec<String>,
}

impl Default for RecursiveCharacterChunker {
    fn default() -> Self {
        Self {
            chunk_size: 256,
            chunk_overlap: 32,
            delimiters: vec![
                "\n\n".to_string(),
                "\n".to_string(),
                ". ".to_string(),
                " ".to_string(),
            ],
        }
    }
}

impl RecursiveCharacterChunker {
    pub fn new(chunk_size: usize, chunk_overlap: usize) -> Self {
        Self {
            chunk_size,
            chunk_overlap,
            ..Default::default()
        }
    }

    fn split_text(&self, text: &str) -> Vec<String> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        if trimmed.len() <= self.chunk_size {
            return vec![trimmed.to_string()];
        }

        let mut chunks = Vec::new();
        let mut start = 0;

        while start < trimmed.len() {
            let mut end = (start + self.chunk_size).min(trimmed.len());

            // If not at the end of the text, try to find a natural boundary
            if end < trimmed.len() {
                let slice = &trimmed[start..end];
                let mut best_split = None;

                for delim in &self.delimiters {
                    if let Some(pos) = slice.rfind(delim) {
                        let candidate = start + pos + delim.len();
                        if candidate > start + (self.chunk_size / 4) {
                            best_split = Some(candidate);
                            break;
                        }
                    }
                }

                if let Some(pos) = best_split {
                    end = pos;
                }
            }

            let chunk_content = trimmed[start..end].trim().to_string();
            if !chunk_content.is_empty() {
                chunks.push(chunk_content);
            }

            if end >= trimmed.len() {
                break;
            }

            // Advance start with overlap
            if end > self.chunk_overlap && (end - self.chunk_overlap) > start {
                start = end - self.chunk_overlap;
            } else {
                start = end;
            }
        }

        chunks
    }
}

impl Chunker for RecursiveCharacterChunker {
    fn chunk(&self, document: &Document) -> Result<Vec<Chunk>, SentryError> {
        if document.content.trim().is_empty() {
            return Err(SentryError::ChunkingError(format!(
                "Document '{}' has empty content",
                document.id
            )));
        }

        let text_slices = self.split_text(&document.content);
        let mut chunks = Vec::with_capacity(text_slices.len());

        for (idx, slice) in text_slices.into_iter().enumerate() {
            let mut chunk = Chunk::new(&document.id, idx, slice);
            chunk.metadata.insert("title".to_string(), document.title.clone());
            for (k, v) in &document.metadata {
                chunk.metadata.insert(k.clone(), v.clone());
            }
            chunks.push(chunk);
        }

        Ok(chunks)
    }
}
