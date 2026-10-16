"""Azure first-party OAuth client_id and resource_id catalog."""


class AzureClientIds:
    """First-party Azure OAuth client (application) IDs."""


    MSAL = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    AZURE_CLI = "04b07795-8542-4c4c-9cb8-f0f09d69f25f"
    AZURE_POWERSHELL = "1950a258-227b-4e31-a9cf-717495945fc2"


    CLOUDSHELL_PORTAL = "b677c290-cf4b-4a8e-a60e-91ba650a4abe"


    WAM_BROKER = "c44b4083-cba6-42be-8e29-b9702cdde539"

    AZURE_PORTAL_OBSERVED = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"


    VISUAL_STUDIO = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1"


    WINDOWS_TERMINAL = "245e1dee-74ef-4257-a8c8-8208296e1dfd"
    GRAPH_POWERSHELL = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    VISUAL_STUDIO_CODE = "aebc6443-996d-45c2-90f0-388ff96faa56"
    MICROSOFT_TEAMS = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    STORAGE_EXPLORER = (
        "c7f5b65f-f7e6-485a-b1cf-c5e22f4dd8b0"
    )


class AzureResourceIds:
    """Azure OAuth resource / audience IDs (token targets)."""

    MICROSOFT_GRAPH = "00000003-0000-0000-c000-000000000000"
    DIGITAL_TWINS = "0b07f429-9f4b-4714-9392-cc5e8e80c8b0"
    UNKNOWN_18A = "18a66f5f-dbdf-4c17-9dd7-1634712a9cbe"
    DATABRICKS = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"
    DEVOPS = "499b84ac-1321-427f-aa17-267ca6975798"
    KUBELOGIN = "6dae42f8-4368-4678-94ff-3960e28e3630"
    IOT_PLUG_PLAY = "822c8694-ad95-4735-9c55-256f7db2f9b4"
    GRAFANA = "ce34e7e5-485f-4d76-964f-b3d2b16d1e4f"
    KEY_VAULT = "cfa8b339-82a2-471a-a3c9-0fc0be7a4093"
