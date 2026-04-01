package client

import (
	"resty.dev/v3"
)

type requestExecutor interface {
	execute(req *resty.Request, method, path string, result any) (*resty.Response, error)
	executeGetBytes(req *resty.Request, path string) (*resty.Response, []byte, error)
	executePaginated(req *resty.Request, path string, mergePage func([]byte) error) (*resty.Response, error)
}

type RequestBuilder struct {
	req      *resty.Request
	executor requestExecutor
	result   any
}

func (b *RequestBuilder) SetHeader(key, value string) *RequestBuilder {
	if value != "" {
		b.req.SetHeader(key, value)
	}
	return b
}

func (b *RequestBuilder) SetQueryParam(key, value string) *RequestBuilder {
	if value != "" {
		b.req.SetQueryParam(key, value)
	}
	return b
}

func (b *RequestBuilder) SetQueryParams(params map[string]string) *RequestBuilder {
	for k, v := range params {
		if v != "" {
			b.req.SetQueryParam(k, v)
		}
	}
	return b
}

func (b *RequestBuilder) SetBody(body any) *RequestBuilder {
	if body != nil {
		b.req.SetBody(body)
	}
	return b
}

func (b *RequestBuilder) SetResult(result any) *RequestBuilder {
	b.result = result
	b.req.SetResult(result)
	return b
}

func (b *RequestBuilder) Get(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "GET", path, b.result)
}

func (b *RequestBuilder) Post(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "POST", path, b.result)
}

func (b *RequestBuilder) Put(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "PUT", path, b.result)
}

func (b *RequestBuilder) Patch(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "PATCH", path, b.result)
}

func (b *RequestBuilder) Delete(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "DELETE", path, b.result)
}

func (b *RequestBuilder) GetBytes(path string) (*resty.Response, []byte, error) {
	return b.executor.executeGetBytes(b.req, path)
}

func (b *RequestBuilder) GetPaginated(path string, mergePage func([]byte) error) (*resty.Response, error) {
	return b.executor.executePaginated(b.req, path, mergePage)
}
