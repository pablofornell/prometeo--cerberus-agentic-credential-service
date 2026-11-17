//! The MCP server handler (ADR-0029): tools, the `cerberus://catalog` resource, and the server info.

use cerberus_api::{ApiError, convert};
use cerberus_core::VaultService;
use cerberus_core::agent_api::{CATALOG_MAX_LIMIT, CatalogQuery};
use cerberus_types::ErrorCode;
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, ErrorData, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse,
    ReadResourceResult, Resource, ResourceContents, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler};
use serde_json::{Map, Value, json};

use crate::call::{Call, UNTRUSTED_LINE, api_error, mark_untrusted, success};
use crate::{CATALOG_URI, schema, tools};

/// What a model reads when it connects.
const INSTRUCTIONS: &str = "Cerberus keeps credentials for you. Find one with find_credentials, \
get it with get_credential, and give the lease back with release_credential when you are done. \
Every secret you get is for the task only: never print it, log it or repeat it in your answer. \
If a tool returns vault_locked, ask the person to unlock the vault, then call vault_status.";

/// The JSON-RPC code of an error that carries a Cerberus error object (the server-error range).
const CERBERUS_ERROR_CODE: i32 = -32000;

/// The MCP server handler. One value per MCP session; cheap to clone.
#[derive(Clone, Debug)]
pub struct CerberusMcp {
    core: VaultService,
}

impl CerberusMcp {
    /// A handler on a vault service. The agent comes from each request (the token layer).
    #[must_use]
    pub fn new(core: VaultService) -> Self {
        Self { core }
    }

    async fn read_catalog(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let call = Call::new(&self.core, context)?;
        let page = call
            .api
            .catalog(
                &call.ctx,
                CatalogQuery {
                    limit: Some(CATALOG_MAX_LIMIT),
                    ..CatalogQuery::default()
                },
            )
            .await
            .map_err(|error| rpc_error(&call.fail(error)))?;
        let page = convert::catalog_page(page);
        let mut body = json!({
            "items": serde_json::to_value(&page.items)
                .map_err(|_| rpc_error(&call.refuse(ErrorCode::Internal)))?,
            "truncated": page.next_cursor.is_some(),
        });
        if mark_untrusted(&mut body)
            && let Some(map) = body.as_object_mut()
        {
            map.insert("notice".to_owned(), json!(UNTRUSTED_LINE));
        }
        let contents = ResourceContents::text(body.to_string(), CATALOG_URI)
            .with_mime_type("application/json");
        Ok(ReadResourceResult::new(vec![contents])
            .with_ttl_ms(0)
            .with_cache_scope(CacheScope::Private))
    }
}

/// A JSON-RPC error whose `data` is the ADR-0021 error object (used by resource reads).
fn rpc_error(error: &ApiError) -> ErrorData {
    let body = serde_json::to_value(error.body()).unwrap_or(Value::Null);
    ErrorData::new(
        rmcp::model::ErrorCode(CERBERUS_ERROR_CODE),
        error.code.as_str(),
        Some(body),
    )
}

impl ServerHandler for CerberusMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = schema::tools().map_err(|error| ErrorData::internal_error(error, None))?;
        Ok(ListToolsResult::with_all_items(tools))
    }

    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        schema::tool(name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let call = Call::new(&self.core, &context)?;
        let arguments: Map<String, Value> = request.arguments.unwrap_or_default();
        let Some(outcome) = tools::run(&request.name, &call, arguments).await else {
            return Err(ErrorData::invalid_params(
                format!("unknown tool `{}`", request.name),
                None,
            ));
        };
        Ok(match outcome {
            Ok(output) => success(output),
            Err(error) => api_error(&error),
        }
        .into())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let catalog = Resource::new(CATALOG_URI, "Cerberus catalog")
            .with_description("Metadata of the credentials you can see. No secret values.")
            .with_mime_type("application/json");
        Ok(ListResourcesResult::with_all_items(vec![catalog]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if request.uri != CATALOG_URI {
            return Err(ErrorData::resource_not_found(
                format!("unknown resource `{}`", request.uri),
                None,
            ));
        }
        Ok(self.read_catalog(&context).await?.into())
    }
}
