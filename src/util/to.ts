export default function to<T>(promise: Promise<T>): Promise<[null, T] | [Error | null]> {
    return promise
        .then((data: T) => {
            return [null, data];
        })
        .catch((err: Error) => [err, null]) as Promise<[null, T] | [Error | null]>;
}
