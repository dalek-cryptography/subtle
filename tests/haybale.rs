extern crate llvm_ir;
extern crate pitchfork;
extern crate subtle;

use pitchfork::{
    AbstractData,
    Config,
    PitchforkConfig,
    Project,
    StructDescriptions,
    check_for_ct_violation,
};

use subtle::ConstantTimeEq;

//  Haybale[-pitchfork] require llvm-sys (LLVM Rust bindings) and boolector
//    llvm-sys and boolector need to be installed as shared libraries prior
//    to compiling this test.
//
//  Generate LLVM bitcode:
//
//      CARGO_INCREMENTAL="" cargo rustc -- -g --emit llvm-bc
//
//  Run test:
//
//      cargo test --test haybale
#[test]
fn test_ct_haybale() {
    let a: u8 = 0x42;
    let b: u8 = 0x43;

    // Use ConstantTimeEq trait to generate LLVM bitcode
    let _ = a.ct_eq(&a.clone());
    let _ = a.ct_eq(&b);

    let c: [u8; 3] = [0x40, 0x41, 0x42];
    let d: [u8; 3] = [0x40, 0x43, 0x41];

    let _ = c.ct_eq(&c.clone());
    let _ = c.ct_eq(&d);

    // Path to generated bitcode
    let mut bc_path = std::env::current_exe().unwrap();
    bc_path.pop();

    let project = Project::from_bc_dir(&bc_path, "bc").unwrap();

    // Get all mangled function names for ConstantTimeEq implementations
    let ct_func_names = project
        .all_functions()
        .filter(|x| x.0.name.contains("ct_eq"))
        .collect::<Vec<(&llvm_ir::Function, &llvm_ir::module::Module)>>();

    // Test each function for constant-time violations
    for func in ct_func_names {
        let result = check_for_ct_violation(&func.0.name,
                                            &project,
                                            Some(vec![AbstractData::pub_pointer_to(AbstractData::secret()), AbstractData::pub_pointer_to(AbstractData::secret())]),
                                            &StructDescriptions::default(),
                                            Config::default(),
                                            &PitchforkConfig::default());

        if result.path_results.len() != 0 {
            panic!("Constant-time result:\n\n{}", &result);
        }
    }
}
