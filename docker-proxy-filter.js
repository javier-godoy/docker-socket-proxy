const allowed = Object.create(null);
const restricted = (process.env.ALLOWED_CONTAINERS || '').split(',').reduce((found, name) => {
    name = name.trim();
    if (name) {
        allowed[name] = true;
    }
    return found || !!name;
}, false);

const descriptiveErrors = process.env.DESCRIPTIVE_ERRORS === '1';
const removeLabels = process.env.REMOVE_LABELS === '1';
const removeEnv = process.env.REMOVE_ENV === '1';

const eventAttributes = {
    container: ['name', 'image'],
    image: ['name'],
};

const actionAttributes = {
    commit: ['comment', 'imageID', 'imageRef'],
    die: ['exitCode', 'execDuration'],
    exec_create: ['execID'],
    exec_start: ['execID'],
    exec_detach: ['execID'],
    exec_die: ['execID', 'exitCode'],
    kill: ['signal'],
    rename: ['oldName'],
    resize: ['height', 'width'],
};

function filterEvent(line) {
    let event;
    try {
        event = JSON.parse(line);
    } catch (e) {
        return null;
    }
    if (!event || typeof event !== 'object') {
        return null;
    }
    const attributes = (event.Actor && event.Actor.Attributes) || {};
    if (restricted && (event.Type !== 'container' || allowed[attributes.name] !== true)) {
        return null;
    }
    const keep = eventAttributes.hasOwnProperty(event.Type) && eventAttributes[event.Type];
    if (!removeLabels || !keep || !event.Actor || !event.Actor.Attributes) {
        return line + '\n';
    }
    const action = event.Type === 'container' && typeof event.Action === 'string' && event.Action.split(':')[0];
    const extra = (action && actionAttributes.hasOwnProperty(action) && actionAttributes[action]) || [];
    event.Actor.Attributes = Object.keys(attributes).reduce((kept, key) => {
        if (keep.includes(key) || extra.includes(key)) {
            kept[key] = attributes[key];
        }
        return kept;
    }, {});
    const timeNano = /"timeNano":\s*(\d+)/.exec(line);
    delete event.timeNano;
    let encoded = JSON.stringify(event);
    if (timeNano) {
        encoded = encoded.slice(0, -1) + ',"timeNano":' + timeNano[1] + '}';
    }
    return encoded + '\n';
}

function eventsHeader(r) {
    if (r.status === 200) {
        delete r.headersOut['Content-Length'];
    }
}

function eventsBody(r, data, flags) {
    if (r.status !== 200) {
        r.sendBuffer(data, flags);
        return;
    }
    const pending = r.rawVariables.docker_proxy_pending;
    const buffer = pending && pending.length ? Buffer.concat([Buffer.from(pending), data]) : Buffer.from(data);
    const output = [];
    let pos = 0;
    let eol;
    while ((eol = buffer.indexOf('\n', pos)) !== -1) {
        const line = filterEvent(buffer.slice(pos, eol).toString());
        if (line !== null) {
            output.push(line);
        }
        pos = eol + 1;
    }
    if (pos < buffer.length || (pending && pending.length)) {
        r.variables.docker_proxy_pending = buffer.slice(pos);
    }
    if (output.length || flags.last) {
        r.sendBuffer(output.join(''), flags);
    }
}

const hopByHop = { 'connection': true, 'content-length': true, 'transfer-encoding': true, 'keep-alive': true };

function isAllowed(name) {
    return typeof name === 'string' && allowed[name.replace(/^\//, '')] === true;
}

function forbid(r, key) {
    if (descriptiveErrors) {
        r.headersOut['docker-proxy-rule'] = 'Location: ' + key + ' (CONTAINER NOT ALLOWED)';
        r.return(403, '403 Forbidden: docker-socket-proxy is configured to not allow access to this function. To enable this function add the container to the ALLOWED_CONTAINERS option.');
    } else {
        r.headersOut['docker-proxy-rule'] = 'Location: Default (BLOCKED)';
        r.return(403, '403 Forbidden: docker-socket-proxy is configured to not allow access to this function.');
    }
}

function reply(r, key, response, body) {
    for (const header in response.headersOut) {
        if (!hopByHop[header.toLowerCase()]) {
            r.headersOut[header] = response.headersOut[header];
        }
    }
    r.headersOut['docker-proxy-rule'] = 'Location: ' + key;
    r.return(response.status, body);
}

async function containerName(r, ref) {
    const response = await r.subrequest('/docker-proxy-inspect/containers/' + encodeURIComponent(ref) + '/json');
    if (response.status === 404) {
        return undefined;
    }
    try {
        return response.status === 200 ? JSON.parse(response.responseText).Name : null;
    } catch (e) {
        return null;
    }
}

function listed(container) {
    return Array.isArray(container.Names) && container.Names.some(isAllowed);
}

function fold(key) {
    return key.toLowerCase().replace(/ſ/g, 's');
}

function fields(object, key) {
    if (!object || typeof object !== 'object' || Array.isArray(object)) {
        return [];
    }
    return Object.keys(object).filter((name) => fold(name) === fold(key)).map((name) => object[name]);
}

async function filterContainers(r, upstream, key, transform) {
    const read = r.method === 'GET' || r.method === 'HEAD';
    const response = await r.subrequest(upstream + r.uri, { args: r.variables.args || '', method: read ? 'GET' : r.method });
    let body = response.responseText;

    if (response.status === 200 && read) {
        let json;
        try {
            json = JSON.parse(body);
        } catch (e) {
            r.return(502);
            return;
        }
        const filtered = await transform(json);
        if (filtered === null) {
            forbid(r, key);
            return;
        }
        if (filtered !== undefined) {
            body = JSON.stringify(filtered) + '\n';
        }
    }

    reply(r, key, response, body);
}

async function authorizeExec(r) {
    const match = /^(?:\/v[\d.]+)?\/exec\/([^/?]+)/.exec(r.variables.request_uri);
    if (!match) {
        r.return(403);
        return;
    }
    const exec = await r.subrequest('/docker-proxy-inspect/exec/' + match[1] + '/json');
    if (exec.status === 404) {
        r.return(204);
        return;
    }
    let containerId;
    try {
        containerId = exec.status === 200 && JSON.parse(exec.responseText).ContainerID;
    } catch (e) {
        containerId = null;
    }
    const name = typeof containerId === 'string' && containerId ? await containerName(r, containerId) : null;
    r.return(isAllowed(name) ? 204 : 403);
}

async function network(r, key) {
    let refs;
    try {
        refs = fields(JSON.parse(r.requestText), 'Container');
    } catch (e) {
        refs = [];
    }
    if (!refs.length) {
        forbid(r, key);
        return;
    }
    for (let i = 0; i < refs.length; i++) {
        const name = typeof refs[i] === 'string' && refs[i] ? await containerName(r, refs[i]) : null;
        if (name !== undefined && !isAllowed(name)) {
            forbid(r, key);
            return;
        }
    }
    const response = await r.subrequest('/docker-proxy-forward' + r.uri, { args: r.variables.args || '', method: 'POST', body: r.requestText });
    reply(r, key, response, response.responseText);
}

function networkConnect(r) {
    return network(r, 'NETWORKS_CONNECT');
}

function networkDisconnect(r) {
    return network(r, 'NETWORKS_DISCONNECT');
}

function inspect(r) {
    return filterContainers(r, '/docker-proxy-inspect', 'CONTAINERS', (container) => {
        if (restricted && !isAllowed(container.Name)) {
            return null;
        }
        if ((removeLabels || removeEnv) && container.Config && typeof container.Config === 'object') {
            if (removeLabels) {
                container.Config.Labels = {};
            }
            if (removeEnv) {
                container.Config.Env = [];
            }
            return container;
        }
    });
}

function filterList(containers) {
    return containers.filter((container) => !restricted || listed(container)).map((container) => {
        if (removeLabels) {
            container.Labels = {};
        }
        return container;
    });
}

function list(r) {
    return filterContainers(r, '/docker-proxy-list', 'CONTAINERS', (containers) => {
        if (!Array.isArray(containers) || !(restricted || removeLabels)) {
            return;
        }
        return filterList(containers);
    });
}

function systemDf(r) {
    return filterContainers(r, '/docker-proxy-list', 'SYSTEM', (usage) => {
        if (Array.isArray(usage.Containers)) {
            usage.Containers = filterList(usage.Containers);
        }
        const containerUsage = usage.ContainerUsage;
        if (containerUsage && Array.isArray(containerUsage.Items)) {
            containerUsage.Items = filterList(containerUsage.Items);
            containerUsage.TotalCount = containerUsage.Items.length;
            containerUsage.ActiveCount = 0;
            containerUsage.TotalSize = 0;
            containerUsage.Reclaimable = 0;
            containerUsage.Items.forEach((container) => {
                const size = container.SizeRw || 0;
                containerUsage.TotalSize += size;
                if (['running', 'paused', 'restarting'].includes(container.State)) {
                    containerUsage.ActiveCount++;
                } else {
                    containerUsage.Reclaimable += size;
                }
            });
        }
        return usage;
    });
}

function networks(r) {
    return filterContainers(r, '/docker-proxy-list', 'NETWORKS', (json) => {
        (Array.isArray(json) ? json : [json]).forEach((network) => {
            const containers = network && network.Containers;
            if (containers && typeof containers === 'object') {
                Object.keys(containers).forEach((id) => {
                    if (!isAllowed(containers[id] && containers[id].Name)) {
                        delete containers[id];
                    }
                });
            }
        });
        return json;
    });
}

async function allowedContainerIds(r) {
    const response = await r.subrequest('/docker-proxy-list/containers/json', { args: 'all=1' });
    const ids = Object.create(null);
    try {
        JSON.parse(response.responseText).forEach((container) => {
            if (listed(container)) {
                ids[container.Id] = true;
            }
        });
    } catch (e) {
        return ids;
    }
    return ids;
}

function images(r) {
    return filterContainers(r, '/docker-proxy-list', 'IMAGES', async (json) => {
        const data = [];
        (Array.isArray(json) ? json : [json]).forEach((image) => {
            (image && Array.isArray(image.Manifests) ? image.Manifests : []).forEach((manifest) => {
                if (manifest && manifest.ImageData && Array.isArray(manifest.ImageData.Containers) && manifest.ImageData.Containers.length) {
                    data.push(manifest.ImageData);
                }
            });
        });
        if (!data.length) {
            return;
        }
        const ids = await allowedContainerIds(r);
        data.forEach((imageData) => {
            imageData.Containers = imageData.Containers.filter((id) => ids[id] === true);
        });
        return json;
    });
}

function references(config) {
    const refs = [];
    const mode = (value) => {
        if (typeof value === 'string' && value.startsWith('container:')) {
            refs.push(value.slice('container:'.length));
        }
    };
    const names = (value) => {
        if (Array.isArray(value)) {
            value.forEach((entry) => {
                if (typeof entry === 'string') {
                    refs.push(entry.split(':')[0]);
                }
            });
        }
    };
    fields(config, 'HostConfig').forEach((hostConfig) => {
        ['NetworkMode', 'PidMode', 'IpcMode', 'Cgroup'].forEach((key) => fields(hostConfig, key).forEach(mode));
        ['VolumesFrom', 'Links'].forEach((key) => fields(hostConfig, key).forEach(names));
    });
    fields(config, 'NetworkingConfig').forEach((networkingConfig) => {
        fields(networkingConfig, 'EndpointsConfig').forEach((endpoints) => {
            if (endpoints && typeof endpoints === 'object') {
                Object.keys(endpoints).forEach((network) => fields(endpoints[network], 'Links').forEach(names));
            }
        });
    });
    return refs.map((ref) => ref.replace(/^\//, ''));
}

async function containerCreate(r) {
    let config = null;
    if (r.requestText) {
        try {
            config = JSON.parse(r.requestText);
        } catch (e) {
            forbid(r, 'CONTAINERS_CREATE');
            return;
        }
    }
    const refs = references(config);
    for (let i = 0; i < refs.length; i++) {
        const name = refs[i] ? await containerName(r, refs[i]) : null;
        if (name !== undefined && !isAllowed(name)) {
            forbid(r, 'CONTAINERS_CREATE');
            return;
        }
    }
    const response = await r.subrequest('/docker-proxy-forward' + r.uri, { args: r.variables.args || '', method: 'POST', body: r.requestText });
    reply(r, 'CONTAINERS_CREATE', response, response.responseText);
}

export default { eventsHeader, eventsBody, inspect, list, authorizeExec, networkConnect, networkDisconnect, systemDf, networks, images, containerCreate };
