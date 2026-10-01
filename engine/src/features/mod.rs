//! "略微完整"特征体系 - 维度定义和数据读取接口
//!
//! 实现"提取时追求高维全面，存储时追求极致压缩"的核心策略：
//! - 静态特征：约 1500-2000 维（PE 结构 ~50 + IAT/EAT ~500 + 字符串 ~1000 + 字节直方图 ~256 + 资源 ~50）
//! - 动态特征：约 300-400 维（API ~200 + 文件 ~50 + 网络 ~50 + 注册表 ~50 + 进程 ~30）
//! - 存储：scipy.sparse CSR 格式 + 特征哈希降维
//! - 坚决不存原始样本（只存特征向量 + 标签 + 统计）
//!
//! 参考 EMBER 项目 (github.com/endgameinc/ember) 的 2381 维标准特征集。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 静态特征维度常量定义。
///
/// 这些常量与 Python 端 `tools/extract_features.py` 中的维度定义保持一致。
/// 任何修改都需要同时更新 Python 端以保持兼容。
pub mod static_dims {
    /// PE 基础结构维度（~50 维）
    pub const PE_STRUCTURE: usize = 50;
    /// IAT/EAT 危险 API 维度（~500 维）
    pub const PE_IAT_API: usize = 512;
    /// 字符串特征维度（~1000 维）
    pub const STRING_FEATURES: usize = 1024;
    /// 字节直方图维度（~256 维）
    pub const BYTE_HISTOGRAM: usize = 256;
    /// 资源与元数据维度（~50 维）
    pub const RESOURCE_METADATA: usize = 50;
    /// 静态特征总维度
    pub const STATIC_TOTAL: usize = PE_STRUCTURE + PE_IAT_API + STRING_FEATURES + BYTE_HISTOGRAM + RESOURCE_METADATA;
}

/// 动态特征维度常量定义。
///
/// 这些常量与 Python 端 `tools/extract_behavior.py` 中的维度定义保持一致。
pub mod dynamic_dims {
    /// API 调用统计维度（~200 维）
    pub const API_CLUSTERS: usize = 200;
    /// 文件操作维度（~50 维）
    pub const FILE_OPERATIONS: usize = 50;
    /// 网络操作维度（~50 维）
    pub const NETWORK_OPERATIONS: usize = 50;
    /// 注册表/持久化维度（~50 维）
    pub const REGISTRY_PERSIST: usize = 50;
    /// 进程/线程操作维度（~30 维）
    pub const PROCESS_THREAD: usize = 30;
    /// 动态特征总维度
    pub const DYNAMIC_TOTAL: usize =
        API_CLUSTERS + FILE_OPERATIONS + NETWORK_OPERATIONS + REGISTRY_PERSIST + PROCESS_THREAD;
}

/// 特征向量元数据（与 .npz 文件中的 meta 字段对应）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureMetadata {
    /// 静态特征维度
    pub static_dim: usize,
    /// 动态特征维度
    pub dynamic_dim: usize,
    /// 总维度
    pub total_dim: usize,
    /// 类别（0=benign, 1=malware）
    pub label: u8,
    /// 家族/家族标签（可选，如 "win32_ebury"）
    pub family: Option<String>,
    /// 源文件 SHA-256（用于追溯，但不存原始样本）
    pub sha256: String,
    /// 提取时间戳（Unix seconds）
    pub extracted_at: u64,
    /// 提取器版本
    pub extractor_version: String,
}

impl FeatureMetadata {
    /// 创建一个新的特征元数据。
    pub fn new(label: u8, sha256: String) -> Self {
        Self {
            static_dim: static_dims::STATIC_TOTAL,
            dynamic_dim: dynamic_dims::DYNAMIC_TOTAL,
            total_dim: static_dims::STATIC_TOTAL + dynamic_dims::DYNAMIC_TOTAL,
            label,
            family: None,
            sha256,
            extracted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            extractor_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// 创建一个带有家族标签的特征元数据。
    pub fn with_family(label: u8, family: String, sha256: String) -> Self {
        let mut meta = Self::new(label, sha256);
        meta.family = Some(family);
        meta
    }
}

/// 特征向量包装。
///
/// 特征向量是 `f32` 数组，长度等于 `static_dim + dynamic_dim`。
/// 存储格式：scipy.sparse.csr_matrix（每行一个样本，每列一个特征）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    /// 静态特征部分（PE 基础 + IAT + 字符串 + 字节直方图 + 资源）
    pub static_features: Vec<f32>,
    /// 动态特征部分（API + 文件 + 网络 + 注册表 + 进程）
    pub dynamic_features: Vec<f32>,
    /// 元数据
    pub metadata: FeatureMetadata,
}

impl FeatureVector {
    /// 创建一个零填充的特征向量。
    pub fn zeros(label: u8, sha256: String) -> Self {
        Self {
            static_features: vec![0.0; static_dims::STATIC_TOTAL],
            dynamic_features: vec![0.0; dynamic_dims::DYNAMIC_TOTAL],
            metadata: FeatureMetadata::new(label, sha256),
        }
    }

    /// 拼接静态 + 动态特征为一维数组。
    pub fn as_flat(&self) -> Vec<f32> {
        let mut flat = self.static_features.clone();
        flat.extend_from_slice(&self.dynamic_features);
        flat
    }

    /// 从一维数组（静态 + 动态）创建特征向量。
    pub fn from_flat(flat: Vec<f32>, metadata: FeatureMetadata) -> Result<Self, String> {
        if flat.len() != metadata.total_dim {
            return Err(format!(
                "expected {} features, got {}",
                metadata.total_dim,
                flat.len()
            ));
        }
        let static_features = flat[..static_dims::STATIC_TOTAL].to_vec();
        let dynamic_features = flat[static_dims::STATIC_TOTAL..].to_vec();
        Ok(Self {
            static_features,
            dynamic_features,
            metadata,
        })
    }
}

/// 特征存储路径（与 Python 端 `tools/extract_features.py` 中的默认路径保持一致）。
pub fn default_feature_dir() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    cwd.join("artifacts").join("features")
}

/// 加载特征元数据（从 .npz 文件的 meta 字段解析）。
///
/// Python 端使用 numpy.savez 保存特征矩阵和元数据（meta 为数组）。
/// 此函数作为占位符——实际的特征加载应在 Python 端完成（scipy.sparse.load_npz）。
pub fn feature_metadata_path(label: u8, sha256: &str) -> PathBuf {
    let sanitized = sha256.chars().take(16).collect::<String>();
    default_feature_dir()
        .join(if label == 1 { "malware" } else { "benign" })
        .join(format!("{}.json", sanitized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_dimensions_match_specification() {
        assert_eq!(static_dims::PE_STRUCTURE, 50);
        assert_eq!(static_dims::PE_IAT_API, 512);
        assert_eq!(static_dims::STRING_FEATURES, 1024);
        assert_eq!(static_dims::BYTE_HISTOGRAM, 256);
        assert_eq!(static_dims::RESOURCE_METADATA, 50);
        assert_eq!(static_dims::STATIC_TOTAL, 1892);
    }

    #[test]
    fn dynamic_dimensions_match_specification() {
        assert_eq!(dynamic_dims::API_CLUSTERS, 200);
        assert_eq!(dynamic_dims::FILE_OPERATIONS, 50);
        assert_eq!(dynamic_dims::NETWORK_OPERATIONS, 50);
        assert_eq!(dynamic_dims::REGISTRY_PERSIST, 50);
        assert_eq!(dynamic_dims::PROCESS_THREAD, 30);
        assert_eq!(dynamic_dims::DYNAMIC_TOTAL, 380);
    }

    #[test]
    fn total_dimension_count() {
        // 静态 + 动态
        assert_eq!(
            static_dims::STATIC_TOTAL + dynamic_dims::DYNAMIC_TOTAL,
            1892 + 380
        );
    }

    #[test]
    fn feature_vector_flat_roundtrip() {
        let original = FeatureVector {
            static_features: vec![0.1; static_dims::STATIC_TOTAL],
            dynamic_features: vec![0.2; dynamic_dims::DYNAMIC_TOTAL],
            metadata: FeatureMetadata::new(1, "abc123".to_string()),
        };
        let flat = original.as_flat();
        assert_eq!(flat.len(), original.metadata.total_dim);
        let recovered = FeatureVector::from_flat(flat, original.metadata.clone()).unwrap();
        assert_eq!(recovered.static_features, original.static_features);
        assert_eq!(recovered.dynamic_features, original.dynamic_features);
    }

    #[test]
    fn zeros_vector_has_correct_dimensions() {
        let v = FeatureVector::zeros(1, "deadbeef".to_string());
        assert_eq!(v.static_features.len(), static_dims::STATIC_TOTAL);
        assert_eq!(v.dynamic_features.len(), dynamic_dims::DYNAMIC_TOTAL);
        assert_eq!(v.metadata.total_dim, static_dims::STATIC_TOTAL + dynamic_dims::DYNAMIC_TOTAL);
        assert_eq!(v.metadata.label, 1);
    }

    #[test]
    fn metadata_includes_extractor_version() {
        let meta = FeatureMetadata::new(0, "cafebabe".to_string());
        assert!(!meta.extractor_version.is_empty());
        assert_eq!(meta.label, 0);
        assert_eq!(meta.sha256, "cafebabe");
    }

    #[test]
    fn metadata_with_family() {
        let meta = FeatureMetadata::with_family(1, "win32_ebury".to_string(), "abc".to_string());
        assert_eq!(meta.family, Some("win32_ebury".to_string()));
        assert_eq!(meta.label, 1);
    }

    #[test]
    fn feature_storage_path_uses_label() {
        let malware_path = feature_metadata_path(1, "abc123def456");
        let benign_path = feature_metadata_path(0, "abc123def456");
        assert!(malware_path.to_string_lossy().contains("malware"));
        assert!(benign_path.to_string_lossy().contains("benign"));
        assert_ne!(malware_path, benign_path);
    }
}
