//! Portable export and import of pre-materialized flat ext4 roots.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use async_compression::tokio::bufread::ZstdEncoder;
use oci_spec::image::ImageManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};

use crate::cache::lock::{flock_unlock, lock_exclusive, open_lock_file};
use crate::ext4::{EXT4_ROOTFS_MATERIALIZER_ABI, validate_rootfs_image};
use crate::{
    CachedImageMetadata, Digest, FlatRootfsRef, GlobalCache, ImageError, ImageResult, Platform,
    Reference,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const PREPARED_ROOT_SCHEMA: u32 = 1;
const COPY_BUFFER_BYTES: usize = 1024 * 1024;

/// Filename containing the prepared-root metadata document.
pub const PREPARED_ROOT_METADATA_FILENAME: &str = "metadata.json";

/// Filename containing the Zstandard-compressed sparse ext4 bytes.
pub const PREPARED_ROOT_PAYLOAD_FILENAME: &str = "rootfs.raw.zst";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Versioned metadata binding a prepared ext4 root to its OCI image inputs.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRootMetadata {
    /// Prepared-root bundle schema version.
    pub schema: u32,
    /// Immutable OCI reference from which the root was materialized.
    pub source_reference: String,
    /// Target platform used by the deterministic materializer.
    pub platform: PreparedRootPlatform,
    /// OCI manifest, configuration, and ordered layer metadata.
    pub image: CachedImageMetadata,
    /// Validated flat-root artifact identity and filesystem statistics.
    pub root: FlatRootfsRef,
}

/// Serializable target platform stored in a prepared-root bundle.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRootPlatform {
    /// OCI operating-system name.
    pub os: String,
    /// OCI CPU architecture name.
    pub architecture: String,
    /// Optional OCI architecture variant.
    pub variant: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Export a cached flat root as a portable prepared-root bundle.
pub async fn export_prepared_root(
    cache: &GlobalCache,
    reference: &Reference,
    platform: &Platform,
    destination: &Path,
) -> ImageResult<PreparedRootMetadata> {
    let image = cache
        .read_image_metadata_async(reference)
        .await?
        .ok_or_else(|| {
            ImageError::ConfigParse(format!("image metadata is not cached for {reference}"))
        })?;
    let manifest_digest = parse_digest(&image.manifest_digest, "image manifest digest")?;
    validate_pinned_reference(reference, &manifest_digest)?;
    let layer_diff_ids = layer_diff_ids(&image)?;
    let root =
        crate::flat::read_current_flat_ref(cache, &manifest_digest, &layer_diff_ids, platform)?
            .ok_or_else(|| {
                ImageError::ConfigParse(format!(
                    "flat rootfs is not materialized for {} on {}",
                    image.manifest_digest,
                    platform_name(platform)
                ))
            })?;
    let metadata = PreparedRootMetadata {
        schema: PREPARED_ROOT_SCHEMA,
        source_reference: reference.to_string(),
        platform: PreparedRootPlatform {
            os: platform.os.to_string(),
            architecture: platform.arch.to_string(),
            variant: platform.variant.clone(),
        },
        image,
        root,
    };
    validate_metadata(&metadata, reference, platform)?;

    tokio::fs::create_dir_all(destination)
        .await
        .map_err(|source| cache_error(destination, source))?;
    let payload = destination.join(PREPARED_ROOT_PAYLOAD_FILENAME);
    let payload_part = part_path(&payload);
    let artifact_digest = parse_digest(&metadata.root.artifact_digest, "flat artifact digest")?;
    let source = cache.flat_blob_path(&artifact_digest);
    compress_file(&source, &payload_part).await?;
    replace_file(&payload_part, &payload).await?;

    let metadata_path = destination.join(PREPARED_ROOT_METADATA_FILENAME);
    let metadata_part = part_path(&metadata_path);
    let bytes = serde_json::to_vec_pretty(&metadata).map_err(|error| {
        ImageError::ConfigParse(format!(
            "failed to serialize prepared-root metadata: {error}"
        ))
    })?;
    write_synchronized(&metadata_part, &bytes).await?;
    replace_file(&metadata_part, &metadata_path).await?;
    Ok(metadata)
}

/// Import and atomically publish a prepared flat root into a Microsandbox cache.
///
/// The caller must authenticate the bundle's provenance through its transport. Import validates
/// the bundle's internal image/root bindings and bytes, but does not rematerialize the OCI layers.
pub async fn import_prepared_root(
    cache: &GlobalCache,
    reference: &Reference,
    platform: &Platform,
    source: &Path,
) -> ImageResult<PreparedRootMetadata> {
    let metadata_path = source.join(PREPARED_ROOT_METADATA_FILENAME);
    let bytes = tokio::fs::read(&metadata_path)
        .await
        .map_err(|source| cache_error(&metadata_path, source))?;
    let metadata = serde_json::from_slice::<PreparedRootMetadata>(&bytes).map_err(|error| {
        ImageError::ConfigParse(format!("failed to parse prepared-root metadata: {error}"))
    })?;
    validate_metadata(&metadata, reference, platform)?;

    let cache = cache.clone();
    let reference = reference.clone();
    let platform = platform.clone();
    let source = source.to_path_buf();
    tokio::task::spawn_blocking(move || {
        import_prepared_root_blocking(&cache, &reference, &platform, &source, metadata)
    })
    .await
    .map_err(|error| ImageError::Io(std::io::Error::other(error)))?
}

fn import_prepared_root_blocking(
    cache: &GlobalCache,
    reference: &Reference,
    platform: &Platform,
    source: &Path,
    metadata: PreparedRootMetadata,
) -> ImageResult<PreparedRootMetadata> {
    let manifest_digest = parse_digest(&metadata.image.manifest_digest, "image manifest digest")?;
    let derivation_digest =
        parse_digest(&metadata.root.derivation_digest, "root derivation digest")?;
    let lock_file = open_lock_file(&cache.flat_lock_path(&derivation_digest))?;
    lock_exclusive(&lock_file)?;
    let _lock_guard = scopeguard::guard(lock_file, |file| {
        let _ = flock_unlock(&file);
    });

    let layer_diff_ids = layer_diff_ids(&metadata.image)?;
    if crate::flat::read_current_flat_ref(cache, &manifest_digest, &layer_diff_ids, platform)?
        .is_none()
    {
        let work_dir = cache.flat_work_dir(&derivation_digest);
        std::fs::create_dir_all(&work_dir).map_err(|source| cache_error(&work_dir, source))?;
        let _work_guard = scopeguard::guard(work_dir.clone(), |path| {
            let _ = std::fs::remove_dir_all(path);
        });
        let candidate = work_dir.join("prepared-root.raw.part");
        let payload = source.join(PREPARED_ROOT_PAYLOAD_FILENAME);
        let (actual_digest, actual_size) =
            decompress_sparse(&payload, &candidate, metadata.root.virtual_size_bytes)?;
        if actual_size != metadata.root.virtual_size_bytes {
            return Err(ImageError::ConfigParse(format!(
                "prepared root size mismatch: expected {}, got {actual_size}",
                metadata.root.virtual_size_bytes
            )));
        }
        if actual_digest != metadata.root.artifact_digest {
            return Err(ImageError::ConfigParse(format!(
                "prepared root digest mismatch: expected {}, got {actual_digest}",
                metadata.root.artifact_digest
            )));
        }
        validate_rootfs_image(&candidate).map_err(|error| {
            ImageError::ConfigParse(format!(
                "prepared root is not a valid ext4 artifact: {error}"
            ))
        })?;
        let artifact_digest = parse_digest(&metadata.root.artifact_digest, "flat artifact digest")?;
        cache.publish_flat_blob(&candidate, &artifact_digest, actual_size)?;
        cache.write_flat_ref(&manifest_digest, &metadata.root)?;
    }

    cache.write_image_metadata(reference, &metadata.image)?;
    Ok(metadata)
}

fn validate_metadata(
    metadata: &PreparedRootMetadata,
    reference: &Reference,
    platform: &Platform,
) -> ImageResult<()> {
    if metadata.schema != PREPARED_ROOT_SCHEMA {
        return Err(ImageError::ConfigParse(format!(
            "unsupported prepared-root schema {}",
            metadata.schema
        )));
    }
    if metadata.source_reference != reference.to_string() {
        return Err(ImageError::ConfigParse(format!(
            "prepared root source mismatch: expected {reference}, got {}",
            metadata.source_reference
        )));
    }
    if metadata.platform.os != platform.os.to_string()
        || metadata.platform.architecture != platform.arch.to_string()
        || metadata.platform.variant != platform.variant
    {
        return Err(ImageError::ConfigParse(format!(
            "prepared root platform mismatch: expected {}, got {}",
            platform_name(platform),
            prepared_platform_name(&metadata.platform)
        )));
    }
    let manifest_digest = parse_digest(&metadata.image.manifest_digest, "image manifest digest")?;
    validate_pinned_reference(reference, &manifest_digest)?;
    validate_image_metadata(&metadata.image)?;
    if metadata.root.schema != 1 || metadata.root.manifest_digest != metadata.image.manifest_digest
    {
        return Err(ImageError::ConfigParse(
            "prepared root does not match its image manifest".to_string(),
        ));
    }
    if metadata.root.materializer_abi != EXT4_ROOTFS_MATERIALIZER_ABI {
        return Err(ImageError::ConfigParse(format!(
            "prepared root materializer ABI mismatch: expected {EXT4_ROOTFS_MATERIALIZER_ABI}, got {}",
            metadata.root.materializer_abi
        )));
    }
    let layer_diff_ids = layer_diff_ids(&metadata.image)?;
    let (expected_derivation, _) =
        crate::flat::flat_derivation_digest(&manifest_digest, &layer_diff_ids, platform);
    if metadata.root.derivation_digest != expected_derivation.to_string() {
        return Err(ImageError::ConfigParse(
            "prepared root derivation digest does not match its inputs".to_string(),
        ));
    }
    parse_digest(&metadata.root.artifact_digest, "flat artifact digest")?;
    Ok(())
}

fn validate_pinned_reference(reference: &Reference, manifest_digest: &Digest) -> ImageResult<()> {
    match reference.digest() {
        Some(digest) if digest == manifest_digest.to_string() => Ok(()),
        Some(digest) => Err(ImageError::ConfigParse(format!(
            "image reference digest {digest} does not match manifest {manifest_digest}"
        ))),
        None => Err(ImageError::ConfigParse(format!(
            "prepared-root source must be pinned by digest: {reference}"
        ))),
    }
}

fn layer_diff_ids(metadata: &CachedImageMetadata) -> ImageResult<Vec<Digest>> {
    metadata
        .layers
        .iter()
        .map(|layer| parse_digest(&layer.diff_id, "layer diff ID"))
        .collect()
}

fn validate_image_metadata(metadata: &CachedImageMetadata) -> ImageResult<()> {
    validate_json_digest(
        "image configuration",
        metadata.raw_config_json.as_bytes(),
        &metadata.config_digest,
    )?;
    let manifest = serde_json::from_str::<ImageManifest>(&metadata.raw_manifest_json)
        .map_err(|error| ImageError::ManifestParse(format!("prepared image manifest: {error}")))?;
    if manifest.config().digest().to_string() != metadata.config_digest {
        return Err(ImageError::ConfigParse(
            "cached config digest does not match the resolved OCI manifest".to_string(),
        ));
    }
    let raw_config_size = u64::try_from(metadata.raw_config_json.len()).map_err(|_| {
        ImageError::ConfigParse("prepared image config length exceeds u64".to_string())
    })?;
    if manifest.config().size() != raw_config_size {
        return Err(ImageError::ConfigParse(
            "cached config size does not match the resolved OCI manifest".to_string(),
        ));
    }
    if manifest.layers().len() != metadata.layers.len() {
        return Err(ImageError::ConfigParse(
            "cached layer count does not match the resolved OCI manifest".to_string(),
        ));
    }
    for (descriptor, cached) in manifest.layers().iter().zip(&metadata.layers) {
        if descriptor.digest().to_string() != cached.digest
            || cached.media_type.as_deref() != Some(descriptor.media_type().as_ref())
            || cached.size_bytes != u64::try_from(descriptor.size()).ok()
        {
            return Err(ImageError::ConfigParse(
                "cached layer metadata does not match the resolved OCI manifest".to_string(),
            ));
        }
    }
    let (parsed_config, parsed_diff_ids) =
        crate::ImageConfig::parse(metadata.raw_config_json.as_bytes())?;
    let parsed_config = serde_json::to_value(parsed_config).map_err(|error| {
        ImageError::ConfigParse(format!(
            "failed to compare parsed image configuration: {error}"
        ))
    })?;
    let cached_config = serde_json::to_value(&metadata.config).map_err(|error| {
        ImageError::ConfigParse(format!(
            "failed to compare cached image configuration: {error}"
        ))
    })?;
    if parsed_config != cached_config {
        return Err(ImageError::ConfigParse(
            "cached image configuration does not match its raw OCI document".to_string(),
        ));
    }
    if parsed_diff_ids
        != metadata
            .layers
            .iter()
            .map(|layer| layer.diff_id.clone())
            .collect::<Vec<_>>()
    {
        return Err(ImageError::ConfigParse(
            "cached layer diff IDs do not match the raw OCI configuration".to_string(),
        ));
    }
    Ok(())
}

fn validate_json_digest(label: &str, bytes: &[u8], expected: &str) -> ImageResult<()> {
    let actual = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    if actual != expected {
        return Err(ImageError::ConfigParse(format!(
            "{label} digest mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn parse_digest(value: &str, label: &str) -> ImageResult<Digest> {
    value
        .parse()
        .map_err(|_| ImageError::ConfigParse(format!("invalid {label}: {value}")))
}

fn platform_name(platform: &Platform) -> String {
    let mut name = format!("{}/{}", platform.os, platform.arch);
    if let Some(variant) = &platform.variant {
        name.push('/');
        name.push_str(variant);
    }
    name
}

fn prepared_platform_name(platform: &PreparedRootPlatform) -> String {
    let mut name = format!("{}/{}", platform.os, platform.architecture);
    if let Some(variant) = &platform.variant {
        name.push('/');
        name.push_str(variant);
    }
    name
}

async fn compress_file(source: &Path, destination: &Path) -> ImageResult<()> {
    let input = tokio::fs::File::open(source)
        .await
        .map_err(|error| cache_error(source, error))?;
    let mut encoder = ZstdEncoder::new(BufReader::new(input));
    let output = tokio::fs::File::create(destination)
        .await
        .map_err(|error| cache_error(destination, error))?;
    let mut output = BufWriter::new(output);
    tokio::io::copy(&mut encoder, &mut output)
        .await
        .map_err(ImageError::Io)?;
    output.flush().await.map_err(ImageError::Io)?;
    output.get_ref().sync_all().await.map_err(ImageError::Io)
}

fn decompress_sparse(
    source: &Path,
    destination: &Path,
    expected_size: u64,
) -> ImageResult<(String, u64)> {
    let input = std::fs::File::open(source).map_err(|error| cache_error(source, error))?;
    let mut decoder = zstd::stream::read::Decoder::new(input).map_err(ImageError::Io)?;
    let mut output =
        std::fs::File::create(destination).map_err(|error| cache_error(destination, error))?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut hasher = Sha256::new();
    let mut written = 0_u64;
    loop {
        let count = decoder.read(&mut buffer).map_err(ImageError::Io)?;
        if count == 0 {
            break;
        }
        let next_size = written.saturating_add(u64::try_from(count).map_err(|_| {
            ImageError::ConfigParse("prepared root length exceeds u64".to_string())
        })?);
        if next_size > expected_size {
            return Err(ImageError::ConfigParse(format!(
                "prepared root exceeds its declared size of {expected_size} bytes"
            )));
        }
        let bytes = &buffer[..count];
        hasher.update(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            output
                .seek(SeekFrom::Current(i64::try_from(count).map_err(|_| {
                    ImageError::ConfigParse("prepared root chunk is too large".to_string())
                })?))
                .map_err(ImageError::Io)?;
        } else {
            output.write_all(bytes).map_err(ImageError::Io)?;
        }
        written = next_size;
    }
    output.set_len(written).map_err(ImageError::Io)?;
    output.sync_all().map_err(ImageError::Io)?;
    Ok((
        format!("sha256:{}", hex::encode(hasher.finalize())),
        written,
    ))
}

async fn write_synchronized(path: &Path, bytes: &[u8]) -> ImageResult<()> {
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|error| cache_error(path, error))?;
    file.write_all(bytes).await.map_err(ImageError::Io)?;
    file.sync_all().await.map_err(ImageError::Io)
}

async fn replace_file(source: &Path, destination: &Path) -> ImageResult<()> {
    if let Err(error) = tokio::fs::remove_file(destination).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(cache_error(destination, error));
    }
    tokio::fs::rename(source, destination)
        .await
        .map_err(|error| cache_error(destination, error))
}

fn part_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

fn cache_error(path: &Path, source: std::io::Error) -> ImageError {
    ImageError::Cache {
        path: path.to_path_buf(),
        source,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::ext4::{Ext4RootfsOptions, materialize_ext4_rootfs};
    use crate::tree::FileTree;
    use crate::{CachedImageMetadata, ImageConfig};

    #[tokio::test]
    async fn round_trips_a_sparse_prepared_root_without_layer_artifacts() {
        let source_dir = tempdir().unwrap();
        let source_cache = GlobalCache::new(source_dir.path()).unwrap();
        let bundle_dir = tempdir().unwrap();
        let platform = Platform::host_linux();
        let raw_config_json = format!(
            r#"{{"architecture":"{}","os":"{}","rootfs":{{"type":"layers","diff_ids":[]}},"config":{{}}}}"#,
            platform.arch, platform.os
        );
        let config_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(raw_config_json.as_bytes()))
        );
        let registry_manifest_json = format!(
            r#"{{
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "config": {{
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "{config_digest}",
                "size": {}
              }},
              "layers": []
            }}"#,
            raw_config_json.len()
        );
        let manifest_digest: Digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(registry_manifest_json.as_bytes()))
        )
        .parse()
        .unwrap();
        // Registry pulls retain the descriptor digest returned for the original bytes, while
        // oci-client reserializes the parsed manifest stored in CachedImageMetadata.
        let raw_manifest_json = serde_json::to_string(
            &serde_json::from_str::<serde_json::Value>(&registry_manifest_json).unwrap(),
        )
        .unwrap();
        assert_ne!(
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(raw_manifest_json.as_bytes()))
            ),
            manifest_digest.to_string()
        );
        let reference: Reference = format!("registry.example/runner@{manifest_digest}")
            .parse()
            .unwrap();
        let (derivation_digest, derivation_bytes) =
            crate::flat::flat_derivation_digest(&manifest_digest, &[], &platform);
        let candidate = source_cache
            .flat_work_dir(&derivation_digest)
            .join("root.raw");
        std::fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        let artifact = materialize_ext4_rootfs(
            &candidate,
            FileTree::new(),
            &Ext4RootfsOptions {
                derivation_digest: derivation_bytes,
                ..Default::default()
            },
        )
        .unwrap();
        let artifact_digest: Digest = format!("sha256:{}", hex::encode(artifact.sha256))
            .parse()
            .unwrap();
        source_cache
            .publish_flat_blob(&candidate, &artifact_digest, artifact.virtual_size_bytes)
            .unwrap();
        let root = FlatRootfsRef {
            schema: 1,
            manifest_digest: manifest_digest.to_string(),
            derivation_digest: derivation_digest.to_string(),
            artifact_digest: artifact_digest.to_string(),
            materializer_abi: artifact.materializer_abi,
            uuid: hex::encode(artifact.uuid),
            virtual_size_bytes: artifact.virtual_size_bytes,
            inode_count: artifact.inode_count,
            content_bytes: artifact.content_bytes,
        };
        source_cache
            .write_flat_ref(&manifest_digest, &root)
            .unwrap();
        let image = CachedImageMetadata {
            manifest_digest: manifest_digest.to_string(),
            config_digest,
            raw_manifest_json,
            raw_config_json,
            config: ImageConfig::default(),
            layers: Vec::new(),
        };
        source_cache
            .write_image_metadata_async(&reference, &image)
            .await
            .unwrap();

        export_prepared_root(&source_cache, &reference, &platform, bundle_dir.path())
            .await
            .unwrap();

        let imported_dir = tempdir().unwrap();
        let imported_cache = GlobalCache::new(imported_dir.path()).unwrap();
        let first_import =
            import_prepared_root(&imported_cache, &reference, &platform, bundle_dir.path());
        let second_import =
            import_prepared_root(&imported_cache, &reference, &platform, bundle_dir.path());
        let (first_import, second_import) = tokio::join!(first_import, second_import);
        let imported = first_import.unwrap();
        assert_eq!(second_import.unwrap().root, root);

        assert_eq!(imported.root, root);
        assert!(
            imported_cache
                .read_image_metadata(&reference)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            imported_cache.read_flat_ref(&manifest_digest).unwrap(),
            Some(root)
        );
        let imported_blob = imported_cache.flat_blob_path(&artifact_digest);
        assert_eq!(
            std::fs::metadata(&imported_blob).unwrap().len(),
            artifact.virtual_size_bytes
        );
        validate_rootfs_image(&imported_blob).unwrap();

        std::fs::write(
            bundle_dir.path().join(PREPARED_ROOT_PAYLOAD_FILENAME),
            b"corrupt",
        )
        .unwrap();
        let corrupt_dir = tempdir().unwrap();
        let corrupt_cache = GlobalCache::new(corrupt_dir.path()).unwrap();
        assert!(
            import_prepared_root(&corrupt_cache, &reference, &platform, bundle_dir.path(),)
                .await
                .is_err()
        );
        assert_eq!(corrupt_cache.read_flat_ref(&manifest_digest).unwrap(), None);
        assert!(!corrupt_cache.flat_work_dir(&derivation_digest).exists());
    }
}
