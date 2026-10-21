
import pytest
from app.analysis.component_extractor import ComponentExtractor
from app.analysis.parser import parser_registry
from app.core.enums import Language
from app.core.models.code import SourceFile
@pytest.fixture
def extractor():
    return ComponentExtractor()
def test_us4_python_extraction(extractor):
    """Verify extracting Python classes, methods, and functions with correct hierarchy."""
    code = """
class AuthenticationManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
    def verify_token(self, token: str) -> bool:
        return token == self.secret_key
def hash_string(data: str) -> str:
    return "hashed_" + data
"""
    src = SourceFile(file_path="auth.py", relative_path="auth.py", language=Language.PYTHON)
    tree = parser_registry.parse_file(src, code)
    components = extractor.extract_components(tree, code, src)
    assert len(components) == 4
    names = [c.name for c in components]
    assert "AuthenticationManager" in names
    assert "__init__" in names
    assert "verify_token" in names
    assert "hash_string" in names
    # Verify method parent relationship
    verify_fn = next(c for c in components if c.name == "verify_token")
    assert verify_fn.component_type == "method"
    assert verify_fn.parent_name == "AuthenticationManager"
    assert verify_fn.start_line > 0
    assert verify_fn.end_line >= verify_fn.start_line
    # Verify standalone function
    hash_fn = next(c for c in components if c.name == "hash_string")
    assert hash_fn.component_type == "function"
    assert hash_fn.parent_name is None
    print("\n[PASS] US4 Python component extraction verified.")
def test_us4_javascript_extraction(extractor):
    """Verify extracting JavaScript classes, methods, and functions."""
    code = """
class PaymentGateway {
    processPayment(amount) {
        return amount > 0;
    }
}
function calculateTax(amount) {
    return amount * 0.15;
}
"""
    src = SourceFile(file_path="payment.js", relative_path="payment.js", language=Language.JAVASCRIPT)
    tree = parser_registry.parse_file(src, code)
    components = extractor.extract_components(tree, code, src)
    assert len(components) == 3
    names = {c.name for c in components}
    assert names == {"PaymentGateway", "processPayment", "calculateTax"}
    method = next(c for c in components if c.name == "processPayment")
    assert method.component_type == "method"
    assert method.parent_name == "PaymentGateway"
    print("\n[PASS] US4 JavaScript component extraction verified.")
def test_us4_java_extraction(extractor):
    """Verify extracting Java classes and methods."""
    code = """
public class AccountService {
    private double balance;
    public AccountService(double initialBalance) {
        this.balance = initialBalance;
    }
    public boolean deposit(double amount) {
        if (amount <= 0) return false;
        this.balance += amount;
        return true;
    }
}
"""
    src = SourceFile(file_path="AccountService.java", relative_path="AccountService.java", language=Language.JAVA)
    tree = parser_registry.parse_file(src, code)
    components = extractor.extract_components(tree, code, src)
    assert len(components) == 3
    names = {c.name for c in components}
    assert "AccountService" in names
    assert "deposit" in names
    deposit_method = next(c for c in components if c.name == "deposit")
    assert deposit_method.component_type == "method"
    assert deposit_method.parent_name == "AccountService"
    print("\n[PASS] US4 Java component extraction verified.")
def test_us4_c_extraction(extractor):
    """Verify extracting C structs and functions."""
    code = """
struct Session {
    int session_id;
    char token[64];
};
int validate_session(struct Session* s) {
    if (s == NULL) return 0;
    return s->session_id > 0;
}
"""
    src = SourceFile(file_path="session.c", relative_path="session.c", language=Language.C)
    tree = parser_registry.parse_file(src, code)
    components = extractor.extract_components(tree, code, src)
    names = [c.name for c in components]
    assert "validate_session" in names
    func = next(c for c in components if c.name == "validate_session")
    assert func.component_type == "function"
    assert func.language == Language.C
    print("\n[PASS] US4 C component extraction verified.")
def test_us4_cpp_extraction(extractor):
    """Verify extracting C++ classes, namespaces, and member functions."""
    code = """
namespace Database {
    class ConnectionPool {
    public:
        void initialize() {
            // init logic
        }
    };
}
"""
    src = SourceFile(file_path="pool.cpp", relative_path="pool.cpp", language=Language.CPP)
    tree = parser_registry.parse_file(src, code)
    components = extractor.extract_components(tree, code, src)
    names = {c.name for c in components}
    assert "ConnectionPool" in names
    assert "initialize" in names
    method = next(c for c in components if c.name == "initialize")
    assert method.component_type == "method"
    assert method.parent_name == "ConnectionPool"
    print("\n[PASS] US4 C++ component extraction verified.")
