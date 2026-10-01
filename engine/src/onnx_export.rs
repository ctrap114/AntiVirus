//! Minimal hand-written protobuf encoding for the ONNX subset needed to
//! export trained MLP detectors. Avoids pulling in generated ONNX bindings;
//! field numbers mirror onnx.proto3 (ONNX 1.x, IR 9).

use prost::Message as _;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ModelProto {
    #[prost(int64, tag = "1")]
    pub ir_version: i64,
    #[prost(string, tag = "2")]
    pub producer_name: String,
    #[prost(message, repeated, tag = "8")]
    pub opset_import: Vec<OperatorSetIdProto>,
    #[prost(message, optional, tag = "7")]
    pub graph: Option<GraphProto>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OperatorSetIdProto {
    #[prost(string, tag = "1")]
    pub domain: String,
    #[prost(int64, tag = "2")]
    pub version: i64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GraphProto {
    #[prost(message, repeated, tag = "1")]
    pub node: Vec<NodeProto>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(message, repeated, tag = "5")]
    pub initializer: Vec<TensorProto>,
    #[prost(message, repeated, tag = "11")]
    pub input: Vec<ValueInfoProto>,
    #[prost(message, repeated, tag = "12")]
    pub output: Vec<ValueInfoProto>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeProto {
    #[prost(string, repeated, tag = "1")]
    pub input: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    pub output: Vec<String>,
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(string, tag = "4")]
    pub op_type: String,
    #[prost(message, repeated, tag = "5")]
    pub attribute: Vec<AttributeProto>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttributeProto {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(float, tag = "2")]
    pub f: f32,
    #[prost(int64, tag = "3")]
    pub i: i64,
    #[prost(bytes = "vec", tag = "4")]
    pub s: Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub t: Option<TensorProto>,
    /// AttributeProto.AttributeType discriminator (FLOAT=1, INT=2, ...).
    #[prost(int32, tag = "20")]
    pub attr_type: i32,
}

pub const ATTR_FLOAT: i32 = 1;
pub const ATTR_INT: i32 = 2;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TensorProto {
    #[prost(int64, repeated, tag = "1")]
    pub dims: Vec<i64>,
    #[prost(int32, tag = "2")]
    pub data_type: i32,
    #[prost(float, repeated, tag = "4")]
    pub float_data: Vec<f32>,
    #[prost(string, tag = "8")]
    pub name: String,
    #[prost(bytes = "vec", tag = "9")]
    pub raw_data: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValueInfoProto {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, optional, tag = "2")]
    pub r#type: Option<TypeProto>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TypeProto {
    #[prost(message, optional, tag = "1")]
    pub tensor_type: Option<TypeProtoTensor>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TypeProtoTensor {
    /// TensorProto.DataType FLOAT == 1.
    #[prost(int32, tag = "1")]
    pub elem_type: i32,
    #[prost(message, optional, tag = "2")]
    pub shape: Option<TensorShapeProto>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TensorShapeProto {
    #[prost(message, repeated, tag = "1")]
    pub dim: Vec<Dimension>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Dimension {
    /// Wire layout of onnx.TensorShapeProto.Dimension: dim_value=1,
    /// dim_param=2 (denotation=3 is unused here).
    #[prost(oneof = "dimension::Value", tags = "1, 2")]
    pub value: Option<dimension::Value>,
}

pub mod dimension {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(int64, tag = "1")]
        DimValue(i64),
        #[prost(string, tag = "2")]
        DimParam(String),
    }
}

// ---------------------------------------------------------------------------
// Graph construction helpers
// ---------------------------------------------------------------------------

const FLOAT: i32 = 1;
const INT64: i32 = 7;

fn dim(value: Option<i64>) -> Dimension {
    Dimension {
        value: Some(match value {
            Some(v) => dimension::Value::DimValue(v),
            None => dimension::Value::DimParam(String::from("batch")),
        }),
    }
}

fn tensor_value_info(name: &str, dims: Vec<Option<i64>>) -> ValueInfoProto {
    ValueInfoProto {
        name: name.to_string(),
        r#type: Some(TypeProto {
            tensor_type: Some(TypeProtoTensor {
                elem_type: FLOAT,
                shape: Some(TensorShapeProto {
                    dim: dims.into_iter().map(dim).collect(),
                }),
            }),
        }),
    }
}

fn float_tensor(name: &str, dims: &[usize], values: &[f32]) -> TensorProto {
    TensorProto {
        dims: dims.iter().map(|v| *v as i64).collect(),
        data_type: FLOAT,
        name: name.to_string(),
        float_data: values.to_vec(),
        raw_data: Vec::new(),
    }
}

fn attr_float(name: &str, value: f32) -> AttributeProto {
    AttributeProto {
        name: name.to_string(),
        f: value,
        i: 0,
        s: Vec::new(),
        t: None,
        attr_type: ATTR_FLOAT,
    }
}

fn attr_int(name: &str, value: i64) -> AttributeProto {
    AttributeProto {
        name: name.to_string(),
        f: 0.0,
        i: value,
        s: Vec::new(),
        t: None,
        attr_type: ATTR_INT,
    }
}

fn gemm_node(name: &str, a: &str, b: &str, c: &str, out: &str) -> NodeProto {
    NodeProto {
        input: vec![a.to_string(), b.to_string(), c.to_string()],
        output: vec![out.to_string()],
        name: name.to_string(),
        op_type: "Gemm".to_string(),
        attribute: vec![
            attr_float("alpha", 1.0),
            attr_float("beta", 1.0),
            attr_int("transB", 1),
        ],
    }
}

/// Serializes the MLP `input → hidden → hidden/2 → logit` network as an ONNX
/// model with dynamic batch support and `[batch, 1, dim]` input layout.
#[allow(clippy::too_many_arguments)]
pub fn export_mlp(
    dim: usize,
    hidden: usize,
    hidden2: usize,
    w1: &[f32],
    b1: &[f32],
    w2: &[f32],
    b2: &[f32],
    w3: &[f32],
    b3: f32,
) -> Result<Vec<u8>, String> {
    let mut initializers = vec![
        float_tensor("fc1.weight", &[hidden, dim], w1),
        float_tensor("fc1.bias", &[hidden], b1),
        float_tensor("fc2.weight", &[hidden2, hidden], w2),
        float_tensor("fc2.bias", &[hidden2], b2),
        float_tensor("output.weight", &[1, hidden2], w3),
        float_tensor("output.bias", &[1], &[b3]),
        // Reshape targets: [-1, dim] and [-1].
        TensorProto {
            dims: vec![2],
            data_type: INT64,
            name: "reshape_in.shape".to_string(),
            float_data: Vec::new(),
            raw_data: (-1i64).to_le_bytes().iter().chain((dim as i64).to_le_bytes().iter()).copied().collect(),
        },
        TensorProto {
            dims: vec![1],
            data_type: INT64,
            name: "reshape_out.shape".to_string(),
            float_data: Vec::new(),
            raw_data: (-1i64).to_le_bytes().to_vec(),
        },
    ];
    initializers.shrink_to_fit();

    let nodes = vec![
        NodeProto {
            input: vec!["input".into(), "reshape_in.shape".into()],
            output: vec!["flat".into()],
            name: "flatten_input".into(),
            op_type: "Reshape".into(),
            attribute: Vec::new(),
        },
        gemm_node("fc1", "flat", "fc1.weight", "fc1.bias", "z1"),
        NodeProto {
            input: vec!["z1".into()],
            output: vec!["a1".into()],
            name: "relu1".into(),
            op_type: "Relu".into(),
            attribute: Vec::new(),
        },
        gemm_node("fc2", "a1", "fc2.weight", "fc2.bias", "z2"),
        NodeProto {
            input: vec!["z2".into()],
            output: vec!["a2".into()],
            name: "relu2".into(),
            op_type: "Relu".into(),
            attribute: Vec::new(),
        },
        gemm_node("output", "a2", "output.weight", "output.bias", "logits2d"),
        NodeProto {
            input: vec!["logits2d".into(), "reshape_out.shape".into()],
            output: vec!["logit".into()],
            name: "squeeze_logits".into(),
            op_type: "Reshape".into(),
            attribute: Vec::new(),
        },
    ];

    let graph = GraphProto {
        node: nodes,
        name: "everbloom_synthetic_detector".to_string(),
        initializer: initializers,
        input: vec![tensor_value_info(
            "input",
            vec![None, Some(1), Some(dim as i64)],
        )],
        output: vec![tensor_value_info("logit", vec![None])],
    };

    let model = ModelProto {
        ir_version: 9,
        producer_name: "everbloom_engine::training".to_string(),
        opset_import: vec![OperatorSetIdProto {
            domain: String::new(),
            version: 17,
        }],
        graph: Some(graph),
    };

    let mut bytes = Vec::new();
    model
        .encode(&mut bytes)
        .map_err(|error| format!("encode onnx: {error}"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_graph_round_trips_through_tract() -> Result<(), String> {
        use tract_onnx::prelude::*;
        let dim = 12usize;
        let hidden = 8usize;
        let hidden2 = 4usize;
        let linear = |size: usize| -> Vec<f32> { (0..size).map(|i| ((i % 7) as f32 - 3.0) * 0.1).collect() };
        let bytes = export_mlp(
            dim,
            hidden,
            hidden2,
            &linear(dim * hidden),
            &linear(hidden),
            &linear(hidden * hidden2),
            &linear(hidden2),
            &linear(hidden2),
            0.25,
        )?;
        // Persist a copy for external inspection during debugging.
        let _ = std::fs::write(
            std::env::temp_dir().join("everbloom_rust_export.onnx"),
            &bytes,
        );
        let model = match tract_onnx::onnx().model_for_read(&mut std::io::Cursor::new(&bytes)) {
            Ok(model) => model,
            Err(error) => panic!("tract failed to parse exported onnx: {error:?}"),
        }
        .into_optimized()
        .map_err(|e| e.to_string())?
        .into_runnable()
        .map_err(|e| e.to_string())?;

        // Build a [1, 1, dim] input and compare against the reference MLP math.
        let values: Vec<f32> = (0..dim).map(|i| ((i as f32) * 0.37 - 1.5).sin()).collect();
        let tensor = Tensor::from_shape(&[1, 1, dim as usize], values.as_slice()).unwrap();
        let run = model
            .run(tvec!(tensor.into_tvalue()))
            .map_err(|e| e.to_string())?;
        let produced: Vec<f32> = run[0]
            .cast_to::<f32>()
            .map_err(|e| e.to_string())?
            .to_plain_array_view::<f32>()
            .map_err(|e| e.to_string())?
            .as_slice()
            .ok_or("output not contiguous")?
            .to_vec();

        let relu = |v: &[f32]| v.iter().map(|x| x.max(0.0)).collect::<Vec<_>>();
        let matvec = |w: &[f32], x: &[f32], rows: usize| -> Vec<f32> {
            (0..rows)
                .map(|r| w[r * x.len()..(r + 1) * x.len()].iter().zip(x).map(|(a, b)| a * b).sum())
                .collect()
        };
        let mut h = relu(&matvec(&linear(dim * hidden), &values, hidden));
        h = relu(&matvec(&linear(hidden * hidden2), &h, hidden2));
        let logit: f32 = linear(hidden2).iter().zip(&h).map(|(a, b)| a * b).sum::<f32>() + 0.25;
        assert!(
            (produced[0] - logit).abs() < 1e-4,
            "tract output {} vs reference {logit}",
            produced[0]
        );
        Ok(())
    }
}
